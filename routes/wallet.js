'use strict';
// routes/wallet.js — MegaFit Solde (prepaid member wallet)
//
// Money-critical. Design invariants (see WALLET_API_SPEC.md handoff):
//  • All amounts are INTEGER CENTIMES. Never floats.
//  • wallet_transactions is APPEND-ONLY. This module NEVER issues UPDATE/DELETE
//    against it — only INSERT + SELECT. (SQLite has no per-table role grants, so
//    append-only is enforced here at the application layer.)
//  • The materialized balance (wallet_balances) is updated in the SAME
//    better-sqlite3 transaction as every ledger insert. better-sqlite3 is
//    synchronous & single-threaded, so a db.transaction() runs atomically and
//    concurrent pays are naturally serialized → "exactly one succeeds".
//  • QR codes are HMAC-signed server-side. On pay we re-read the price from the
//    DB and NEVER trust the price embedded in the QR.
//  • Every money mutation (pay + admin recharge/refund) is IDEMPOTENT: it carries
//    an Idempotency-Key bound to a fingerprint of the request. Same key + same
//    request → replay the stored response, never re-charge. Same key + DIFFERENT
//    request → 409 IDEMPOTENCY_KEY_REUSED (never silently return the old charge).
//
// Member endpoints (/wallet/*) are gated behind WALLET_ENABLED. Until it is
// "true" they return 404, which the mobile app already treats as
// "wallet not launched yet". Flip it on only once the byte-for-byte member
// contract is confirmed against the spec.

const { Router } = require('express');
const crypto = require('crypto');

// ── Tunables (centimes) ──────────────────────────────────────────────────────
const CURRENCY          = process.env.WALLET_CURRENCY || 'MGD';
const MAX_PAY_CENTIMES  = 50000;   // ≤ 500 Đ per transaction
const MAX_DAILY_CENTIMES = 200000; // ≤ 2000 Đ per member per day
const MAX_RECHARGE_CENTIMES = 500000; // ≤ 5000 Đ per recharge op
const BIG_RECHARGE_CENTIMES = 100000; // > 1000 Đ needs a second confirmation
const PAY_RATE_MAX      = 10;      // ≤ 10 pays / minute / member
const PAY_RATE_WINDOW_MS = 60 * 1000;
const HEX64 = /^[0-9a-f]{64}$/i;   // a SHA-256 HMAC hex digest, exactly

module.exports = function walletRouter(deps) {
  const { db, admin, lc } = deps;
  const sdb = lc.db; // the SQLite handle (source of truth for the ledger)
  const router = Router();

  const WALLET_ENABLED = String(process.env.WALLET_ENABLED || '').toLowerCase() === 'true';
  const SECRET      = process.env.WALLET_QR_SECRET || '';
  const SECRET_PREV = process.env.WALLET_QR_SECRET_PREV || '';
  if (!SECRET) console.warn('⚠️  WALLET_QR_SECRET is not set — QR signing/verification will fail.');

  // ── Schema (idempotent) ─────────────────────────────────────────────────────
  sdb.exec(`
    CREATE TABLE IF NOT EXISTS wallet_products (
      id             TEXT PRIMARY KEY,
      name           TEXT NOT NULL,
      price_centimes INTEGER NOT NULL,
      gym_id         TEXT,
      active         INTEGER NOT NULL DEFAULT 1,
      created_at     TEXT,
      updated_at     TEXT
    );

    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id                     TEXT PRIMARY KEY,
      member_id              TEXT NOT NULL,
      type                   TEXT NOT NULL,          -- 'recharge' | 'purchase' | 'refund'
      amount_centimes        INTEGER NOT NULL,       -- signed: + credit, - debit
      balance_after_centimes INTEGER NOT NULL,
      method                 TEXT,                   -- recharge: cash|card|promo ; purchase: 'wallet'
      product_id             TEXT,
      product_name           TEXT,
      original_txn_id        TEXT,                   -- refunds reference the original
      admin_id               TEXT,
      idempotency_key        TEXT,
      request_hash           TEXT,                   -- fingerprint of the request the key is bound to
      note                   TEXT,
      ip                     TEXT,
      gym_id                 TEXT,
      response_json          TEXT,                   -- stored money-mutation response for replay
      created_at             TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_wallet_txn_member ON wallet_transactions(member_id, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_txn_idem
      ON wallet_transactions(member_id, idempotency_key)
      WHERE idempotency_key IS NOT NULL;

    CREATE TABLE IF NOT EXISTS wallet_balances (
      member_id        TEXT PRIMARY KEY,
      balance_centimes INTEGER NOT NULL DEFAULT 0,
      updated_at       TEXT
    );
  `);
  // Migration for DBs created before request_hash existed.
  try { sdb.exec('ALTER TABLE wallet_transactions ADD COLUMN request_hash TEXT;'); } catch { /* already there */ }

  // ── Prepared statements ─────────────────────────────────────────────────────
  const stmtBalance      = sdb.prepare('SELECT balance_centimes FROM wallet_balances WHERE member_id = ?');
  const stmtUpsertBal    = sdb.prepare(`INSERT INTO wallet_balances (member_id, balance_centimes, updated_at)
                                        VALUES (@member_id, @balance_centimes, @updated_at)
                                        ON CONFLICT(member_id) DO UPDATE SET
                                          balance_centimes = @balance_centimes, updated_at = @updated_at`);
  const stmtInsertTxn    = sdb.prepare(`INSERT INTO wallet_transactions
    (id, member_id, type, amount_centimes, balance_after_centimes, method, product_id, product_name,
     original_txn_id, admin_id, idempotency_key, request_hash, note, ip, gym_id, response_json, created_at)
    VALUES
    (@id, @member_id, @type, @amount_centimes, @balance_after_centimes, @method, @product_id, @product_name,
     @original_txn_id, @admin_id, @idempotency_key, @request_hash, @note, @ip, @gym_id, @response_json, @created_at)`);
  const stmtTxnByIdem    = sdb.prepare('SELECT * FROM wallet_transactions WHERE member_id = ? AND idempotency_key = ?');
  const stmtTxnById      = sdb.prepare('SELECT * FROM wallet_transactions WHERE id = ?');
  const stmtDailySpend   = sdb.prepare(`SELECT COALESCE(SUM(-amount_centimes), 0) AS spent
                                        FROM wallet_transactions
                                        WHERE member_id = ? AND type = 'purchase' AND created_at >= ?`);
  const stmtRefundedSoFar = sdb.prepare(`SELECT COALESCE(SUM(amount_centimes),0) AS refunded
                                         FROM wallet_transactions
                                         WHERE type = 'refund' AND original_txn_id = ?`);

  const stmtProductById  = sdb.prepare('SELECT * FROM wallet_products WHERE id = ?');
  const stmtProductsAll  = sdb.prepare('SELECT * FROM wallet_products ORDER BY active DESC, name ASC');
  const stmtInsertProduct = sdb.prepare(`INSERT INTO wallet_products (id, name, price_centimes, gym_id, active, created_at, updated_at)
                                         VALUES (@id, @name, @price_centimes, @gym_id, @active, @created_at, @updated_at)`);
  const stmtUpdateProduct = sdb.prepare(`UPDATE wallet_products SET name=@name, price_centimes=@price_centimes,
                                         gym_id=@gym_id, active=@active, updated_at=@updated_at WHERE id=@id`);
  const stmtTxnByMember  = sdb.prepare(`SELECT * FROM wallet_transactions WHERE member_id = ?
                                        ORDER BY created_at DESC, rowid DESC LIMIT ?`);
  const stmtTxnByMemberBefore = sdb.prepare(`SELECT * FROM wallet_transactions WHERE member_id = ? AND created_at < ?
                                             ORDER BY created_at DESC, rowid DESC LIMIT ?`);

  // ── Helpers ─────────────────────────────────────────────────────────────────
  const nowIso = () => new Date().toISOString();
  const genId  = (p) => `${p}_${Date.now().toString(36)}_${crypto.randomBytes(5).toString('hex')}`;
  const getBalance = (memberId) => stmtBalance.get(memberId)?.balance_centimes ?? 0;
  const startOfTodayIso = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.toISOString(); };
  const fingerprint = (parts) => crypto.createHash('sha256').update(parts.join('|')).digest('hex');
  const isUniqueViolation = (e) => e && (e.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
    /UNIQUE constraint failed: wallet_transactions\.member_id/.test(String(e.message || '')));

  // HMAC over the canonical string "{v}|{itemId}|{name}|{price}" (price in centimes).
  const signBase = (v, itemId, name, priceCentimes, secret) =>
    crypto.createHmac('sha256', secret).update(`${v}|${itemId}|${name}|${priceCentimes}`).digest('hex');

  const signPayload = (product) => {
    const v = 1;
    const price = product.price_centimes;
    const sig = signBase(v, product.id, product.name, price, SECRET);
    // Exact QR JSON — the mobile app scans this and posts it back to /wallet/pay.
    // `t` is the envelope type the app requires (t === "megafit.pay") — NOT part of
    // the HMAC message, only v|itemId|name|price is signed.
    return { v, t: 'megafit.pay', itemId: product.id, name: product.name, price, sig };
  };

  // Constant-time hex compare. Rejects anything that is not exactly 64 hex chars
  // (prevents Buffer.from(...,'hex') truncation-malleability: "<valid64>zz" would
  // otherwise decode to the same bytes and compare equal).
  const safeEqualHex = (a, b) => {
    if (!HEX64.test(String(a || '')) || !HEX64.test(String(b || ''))) return false;
    try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
    catch { return false; }
  };

  // Verify against current secret, then previous (rotation support).
  const verifyQrSig = (qr) => {
    const { v, itemId, name, price, sig } = qr;
    if (v == null || !itemId || name == null || price == null || !sig) return false;
    if (SECRET && safeEqualHex(sig, signBase(v, itemId, name, price, SECRET))) return true;
    if (SECRET_PREV && safeEqualHex(sig, signBase(v, itemId, name, price, SECRET_PREV))) return true;
    return false;
  };

  // Mirror a ledger row to Firestore for cloud backup/audit (best-effort).
  const mirror = (row) => {
    try {
      db.collection('wallet_transactions').doc(row.id).set({
        ...row, createdAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});
    } catch { /* ignore */ }
  };

  // Format a stored ledger row into the member-facing JSON shape (exact contract).
  const toApiTxn = (r) => ({
    id: r.id,
    type: r.type,
    amountCentimes: r.amount_centimes,
    balanceAfterCentimes: r.balance_after_centimes,
    itemName: r.product_name || null,
    method: r.method || null,
    createdAt: r.created_at,
  });

  // Look up an idempotency record and decide replay vs reuse-conflict.
  // → { replay: <stored response obj> } | { conflict: true } | null (no record)
  const idemLookup = (memberId, key, requestHash) => {
    const row = stmtTxnByIdem.get(memberId, key);
    if (!row) return null;
    if (row.request_hash && requestHash && row.request_hash !== requestHash) return { conflict: true };
    let body;
    try { body = JSON.parse(row.response_json); } catch { body = { transactionId: row.id, balanceAfterCentimes: row.balance_after_centimes }; }
    return { replay: body };
  };

  // ── In-memory per-member pay rate limiter ───────────────────────────────────
  const payHits = new Map(); // memberId -> [timestamps]
  const rateLimited = (memberId) => {
    const now = Date.now();
    const arr = (payHits.get(memberId) || []).filter((t) => now - t < PAY_RATE_WINDOW_MS);
    arr.push(now);
    payHits.set(memberId, arr);
    return arr.length > PAY_RATE_MAX;
  };

  // ── Member auth (Firebase ID token; uid == member doc id) ───────────────────
  // The SAME Firebase project also mints coach tokens (uid = "coach_<id>"), so we
  // must positively confirm the identity is a real, active member — not just that
  // the token is cryptographically valid.
  async function verifyMemberToken(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'UNAUTHENTICATED' });
    let uid;
    try {
      const decoded = await admin.auth().verifyIdToken(token);
      uid = decoded.uid;
      if (decoded.role === 'coach' || String(uid || '').startsWith('coach_')) {
        return res.status(403).json({ error: 'NOT_A_MEMBER' });
      }
    } catch {
      return res.status(401).json({ error: 'UNAUTHENTICATED' });
    }
    try {
      const snap = await db.collection('members').doc(String(uid)).get();
      if (!snap.exists) return res.status(403).json({ error: 'NOT_A_MEMBER' });
      if (snap.data()?.status?.active === false) return res.status(403).json({ error: 'MEMBERSHIP_INACTIVE' });
    } catch {
      return res.status(503).json({ error: 'MEMBER_LOOKUP_FAILED' });
    }
    req.memberId = String(uid);
    next();
  }

  // Launch switch: member endpoints 404 until the wallet is turned on.
  const walletGate = (req, res, next) => {
    if (!WALLET_ENABLED) return res.status(404).json({ error: 'WALLET_NOT_LAUNCHED' });
    next();
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // MEMBER ENDPOINTS  (mobile app) — must match WALLET_API_SPEC.md byte-for-byte
  // ═══════════════════════════════════════════════════════════════════════════

  // GET /wallet/balance
  router.get('/wallet/balance', walletGate, verifyMemberToken, (req, res) => {
    res.json({ balanceCentimes: getBalance(req.memberId), currency: CURRENCY });
  });

  // GET /wallet/transactions?limit&before   (newest-first, paginated)
  router.get('/wallet/transactions', walletGate, verifyMemberToken, (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const before = req.query.before ? String(req.query.before) : null;
    const rows = before
      ? stmtTxnByMemberBefore.all(req.memberId, before, limit)
      : stmtTxnByMember.all(req.memberId, limit);
    const transactions = rows.map(toApiTxn);
    const nextBefore = rows.length === limit ? rows[rows.length - 1].created_at : null;
    res.json({ transactions, nextBefore });
  });

  // POST /wallet/pay  — the money-critical one.
  router.post('/wallet/pay', walletGate, verifyMemberToken, (req, res) => {
    const memberId = req.memberId;
    const idemKey = (req.headers['idempotency-key'] || '').trim();
    if (!idemKey) return res.status(400).json({ error: 'IDEMPOTENCY_KEY_REQUIRED' });

    // 1) Parse the scanned QR payload (accept {qr:{…}} or the fields at top level)
    const qr = req.body?.qr || req.body || {};

    // 2) Verify HMAC (constant-time) BEFORE trusting anything in the QR
    if (!verifyQrSig(qr)) return res.status(400).json({ error: 'INVALID_QR' });

    // 3) Re-read the product from the DB — never trust the QR's price
    const product = stmtProductById.get(String(qr.itemId));
    if (!product || !product.active) return res.status(410).json({ error: 'PRODUCT_INACTIVE' });
    const price = product.price_centimes;

    // 4) Per-transaction limit
    if (price > MAX_PAY_CENTIMES) return res.status(400).json({ error: 'AMOUNT_TOO_LARGE' });

    // 5) Idempotency: the key is bound to (member, item, price). Same key + same
    //    request → replay; same key + different request → conflict (never charge
    //    the old amount and report it as this purchase).
    const reqHash = fingerprint(['pay', memberId, product.id, price]);
    const pre = idemLookup(memberId, idemKey, reqHash);
    if (pre?.conflict) return res.status(409).json({ error: 'IDEMPOTENCY_KEY_REUSED' });
    if (pre?.replay) return res.status(200).json(pre.replay);

    // 6) Rate limit (only genuinely new charges reach here)
    if (rateLimited(memberId)) return res.status(429).json({ error: 'RATE_LIMITED' });

    // 7) Atomic: daily-limit + balance check + debit, all in one SQLite transaction.
    const doPay = sdb.transaction(() => {
      const spentToday = stmtDailySpend.get(memberId, startOfTodayIso()).spent || 0;
      if (spentToday + price > MAX_DAILY_CENTIMES) return { http: 429, body: { error: 'DAILY_LIMIT_EXCEEDED' } };

      const bal = getBalance(memberId);
      if (bal < price) return { http: 409, body: { error: 'INSUFFICIENT_FUNDS', balanceCentimes: bal } };

      const newBal = bal - price; // guaranteed ≥ 0 by the check above
      const id = genId('wtx');
      const created_at = nowIso();
      // Exact /wallet/pay success contract the app parses.
      const response = { status: 'ok', transactionId: id, itemName: product.name, chargedCentimes: price, balanceAfterCentimes: newBal };
      const row = {
        id, member_id: memberId, type: 'purchase', amount_centimes: -price, balance_after_centimes: newBal,
        method: null, product_id: product.id, product_name: product.name, original_txn_id: null,
        admin_id: null, idempotency_key: idemKey, request_hash: reqHash, note: null, ip: req.ip,
        gym_id: product.gym_id || null, response_json: JSON.stringify(response), created_at,
      };
      stmtInsertTxn.run(row);
      stmtUpsertBal.run({ member_id: memberId, balance_centimes: newBal, updated_at: created_at });
      return { http: 200, body: response, row };
    });

    let result;
    try {
      result = doPay();
    } catch (e) {
      // A concurrent request with the same idem key won the unique index; replay it.
      if (isUniqueViolation(e)) {
        const again = idemLookup(memberId, idemKey, reqHash);
        if (again?.conflict) return res.status(409).json({ error: 'IDEMPOTENCY_KEY_REUSED' });
        if (again?.replay) return res.status(200).json(again.replay);
      }
      console.error('POST /wallet/pay error:', e);
      return res.status(500).json({ error: 'SERVER_ERROR' });
    }
    if (result.row) mirror(result.row);
    return res.status(result.http).json(result.body);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // ADMIN ENDPOINTS  (dashboard) — Azure token + admin only. Never a member token.
  // ═══════════════════════════════════════════════════════════════════════════
  const { verifyAzureToken, requireAdmin } = require('../middleware/auth');
  const adminOnly = [verifyAzureToken, requireAdmin];
  // Recharge desk is run by managers too — allow admin OR manager on recharge and
  // the member-balance read, but scope managers to their assigned gym.
  const requireAdminOrManager = (req, res, next) =>
    (req.isAdmin || req.isManager) ? next() : res.status(403).json({ error: 'FORBIDDEN' });
  const adminOrManager = [verifyAzureToken, requireAdminOrManager];

  // Load a member's gym for scoping. exists:false = no member; exists:null = lookup failed.
  const getMemberGym = async (memberId) => {
    try {
      const s = await db.collection('members').doc(String(memberId)).get();
      if (!s.exists) return { exists: false };
      const d = s.data() || {};
      return { exists: true, gymId: d.gymId || d.gym_id || d.location || null };
    } catch { return { exists: null }; }
  };
  // Admin → any gym. Manager → only their assigned gym (fail-open if gym unknown).
  const managerCanTouch = (req, gymId) =>
    req.isAdmin || !gymId || (typeof req.hasAccessToGym === 'function' && req.hasAccessToGym(gymId));

  // Signed credit/refund helper — append-only + materialized balance, atomic, idempotent.
  // Returns { replay } if the idem key already resolved this exact request.
  const applyCredit = ({ memberId, amountCentimes, type, method, note, adminId, ip, gymId, originalTxnId, idemKey, reqHash }) => {
    const pre = idemLookup(memberId, idemKey, reqHash);
    if (pre?.conflict) return { conflict: true };
    if (pre?.replay) return { replay: pre.replay };

    const apply = sdb.transaction(() => {
      // For refunds, enforce the over-refund cap INSIDE the transaction.
      if (type === 'refund' && originalTxnId) {
        const orig = stmtTxnById.get(originalTxnId);
        const origAmount = orig ? Math.abs(orig.amount_centimes) : 0;
        const already = stmtRefundedSoFar.get(originalTxnId).refunded || 0;
        if (amountCentimes + already > origAmount) return { over: origAmount - already };
      }
      const bal = getBalance(memberId);
      const newBal = bal + amountCentimes;
      const id = genId(type === 'refund' ? 'wrf' : 'wrc');
      const created_at = nowIso();
      const response = { ok: true, transactionId: id, balanceAfterCentimes: newBal, currency: CURRENCY };
      const row = {
        id, member_id: memberId, type, amount_centimes: amountCentimes, balance_after_centimes: newBal,
        method: method || null, product_id: null, product_name: null, original_txn_id: originalTxnId || null,
        admin_id: adminId || null, idempotency_key: idemKey || null, request_hash: reqHash || null,
        note: note || null, ip: ip || null, gym_id: gymId || null, response_json: JSON.stringify(response), created_at,
      };
      stmtInsertTxn.run(row);
      stmtUpsertBal.run({ member_id: memberId, balance_centimes: newBal, updated_at: created_at });
      return { response, row };
    });

    let r;
    try { r = apply(); }
    catch (e) {
      if (isUniqueViolation(e)) {
        const again = idemLookup(memberId, idemKey, reqHash);
        if (again?.conflict) return { conflict: true };
        if (again?.replay) return { replay: again.replay };
      }
      throw e;
    }
    if (r.over != null) return { over: r.over };
    mirror(r.row);
    return { response: r.response };
  };

  // POST /admin/wallet/recharge  { memberId, amountCentimes, method, note, confirm }  + Idempotency-Key
  router.post('/admin/wallet/recharge', ...adminOrManager, async (req, res) => {
    const idemKey = (req.headers['idempotency-key'] || '').trim();
    if (!idemKey) return res.status(400).json({ error: 'IDEMPOTENCY_KEY_REQUIRED' });
    const { memberId, amountCentimes, method, note, confirm } = req.body || {};
    const amt = Math.round(Number(amountCentimes));
    if (!memberId || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'INVALID_INPUT' });
    if (amt > MAX_RECHARGE_CENTIMES) return res.status(400).json({ error: 'AMOUNT_TOO_LARGE', maxCentimes: MAX_RECHARGE_CENTIMES });
    if (!['cash', 'card', 'promo'].includes(method)) return res.status(400).json({ error: 'INVALID_METHOD' });
    // Large recharges require a second confirmation step.
    if (amt > BIG_RECHARGE_CENTIMES && !confirm) return res.status(409).json({ error: 'CONFIRM_REQUIRED', thresholdCentimes: BIG_RECHARGE_CENTIMES });

    const mg = await getMemberGym(memberId);
    if (mg.exists === false) return res.status(404).json({ error: 'MEMBER_NOT_FOUND' });
    if (!managerCanTouch(req, mg.gymId)) return res.status(403).json({ error: 'FORBIDDEN_GYM' });

    const reqHash = fingerprint(['recharge', memberId, amt, method]);
    const r = applyCredit({
      memberId, amountCentimes: amt, type: 'recharge', method, note,
      adminId: req.user?.preferred_username || req.user?.oid, ip: req.ip, idemKey, reqHash,
    });
    if (r.conflict) return res.status(409).json({ error: 'IDEMPOTENCY_KEY_REUSED' });
    if (r.replay) return res.status(200).json(r.replay);
    res.json(r.response);
  });

  // POST /admin/wallet/refund  { memberId, originalTransactionId, amountCentimes, note }  + Idempotency-Key
  router.post('/admin/wallet/refund', ...adminOnly, async (req, res) => {
    const idemKey = (req.headers['idempotency-key'] || '').trim();
    if (!idemKey) return res.status(400).json({ error: 'IDEMPOTENCY_KEY_REQUIRED' });
    const { memberId, originalTransactionId, amountCentimes, note } = req.body || {};
    const amt = Math.round(Number(amountCentimes));
    if (!memberId || !originalTransactionId || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'INVALID_INPUT' });

    const orig = stmtTxnById.get(String(originalTransactionId));
    if (!orig || orig.member_id !== memberId) return res.status(404).json({ error: 'ORIGINAL_NOT_FOUND' });
    if (orig.type !== 'purchase') return res.status(400).json({ error: 'NOT_REFUNDABLE' });

    const reqHash = fingerprint(['refund', memberId, orig.id, amt]);
    const r = applyCredit({
      memberId, amountCentimes: amt, type: 'refund', method: orig.method, note,
      adminId: req.user?.preferred_username || req.user?.oid, ip: req.ip,
      gymId: orig.gym_id, originalTxnId: orig.id, idemKey, reqHash,
    });
    if (r.conflict) return res.status(409).json({ error: 'IDEMPOTENCY_KEY_REUSED' });
    if (r.over != null) return res.status(400).json({ error: 'REFUND_EXCEEDS_ORIGINAL', remainingCentimes: r.over });
    if (r.replay) return res.status(200).json(r.replay);
    res.json(r.response);
  });

  // ── Products CRUD ──────────────────────────────────────────────────────────
  router.get('/admin/wallet/products', ...adminOnly, (req, res) => {
    res.json({ products: stmtProductsAll.all().map((p) => ({
      id: p.id, name: p.name, priceCentimes: p.price_centimes, gymId: p.gym_id, active: !!p.active,
      createdAt: p.created_at, updatedAt: p.updated_at,
    })) });
  });

  router.post('/admin/wallet/products', ...adminOnly, (req, res) => {
    const { name, priceCentimes, gymId } = req.body || {};
    const price = Math.round(Number(priceCentimes));
    if (!name || !name.trim() || !Number.isFinite(price) || price <= 0) return res.status(400).json({ error: 'INVALID_INPUT' });
    const id = genId('prd');
    const now = nowIso();
    stmtInsertProduct.run({ id, name: name.trim(), price_centimes: price, gym_id: gymId || null, active: 1, created_at: now, updated_at: now });
    res.json({ ok: true, id });
  });

  router.put('/admin/wallet/products/:id', ...adminOnly, (req, res) => {
    const p = stmtProductById.get(req.params.id);
    if (!p) return res.status(404).json({ error: 'NOT_FOUND' });
    const name = req.body?.name != null ? String(req.body.name).trim() : p.name;
    const price = req.body?.priceCentimes != null ? Math.round(Number(req.body.priceCentimes)) : p.price_centimes;
    const active = req.body?.active != null ? (req.body.active ? 1 : 0) : p.active;
    const gymId = req.body?.gymId !== undefined ? (req.body.gymId || null) : p.gym_id;
    if (!name || !Number.isFinite(price) || price <= 0) return res.status(400).json({ error: 'INVALID_INPUT' });
    stmtUpdateProduct.run({ id: p.id, name, price_centimes: price, gym_id: gymId, active, updated_at: nowIso() });
    res.json({ ok: true });
  });

  // POST /admin/wallet/products/:id/qr → the signed payload to encode & print.
  router.post('/admin/wallet/products/:id/qr', ...adminOnly, (req, res) => {
    const p = stmtProductById.get(req.params.id);
    if (!p) return res.status(404).json({ error: 'NOT_FOUND' });
    if (!SECRET) return res.status(500).json({ error: 'QR_SECRET_NOT_CONFIGURED' });
    res.json({ payload: signPayload(p), product: { id: p.id, name: p.name, priceCentimes: p.price_centimes } });
  });

  // GET /admin/wallet/members/:id/transactions  (support view + recharge-screen balance)
  router.get('/admin/wallet/members/:id/transactions', ...adminOrManager, async (req, res) => {
    if (!req.isAdmin) {
      const mg = await getMemberGym(req.params.id);
      if (mg.exists === false) return res.status(404).json({ error: 'MEMBER_NOT_FOUND' });
      if (!managerCanTouch(req, mg.gymId)) return res.status(403).json({ error: 'FORBIDDEN_GYM' });
    }
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    const rows = stmtTxnByMember.all(req.params.id, limit);
    res.json({
      balanceCentimes: getBalance(req.params.id),
      currency: CURRENCY,
      transactions: rows.map((r) => ({ ...toApiTxn(r), note: r.note || null, adminId: r.admin_id, productId: r.product_id, originalTxnId: r.original_txn_id, ip: r.ip })),
    });
  });

  // GET /admin/wallet/report/daily?date=YYYY-MM-DD  (recharges vs purchases, per product)
  // Uses a LOCAL-day window to match the enforced daily limit (startOfTodayIso).
  router.get('/admin/wallet/report/daily', ...adminOnly, (req, res) => {
    const date = (req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(req.query.date)) ? req.query.date : new Date().toISOString().slice(0, 10);
    const dayStart = new Date(`${date}T00:00:00`);          // local midnight
    const dayEnd = new Date(dayStart); dayEnd.setDate(dayEnd.getDate() + 1);
    const start = dayStart.toISOString();
    const end = dayEnd.toISOString();
    const rows = sdb.prepare('SELECT * FROM wallet_transactions WHERE created_at >= ? AND created_at < ?').all(start, end);

    let rechargeTotal = 0, purchaseTotal = 0, refundTotal = 0, rechargeCount = 0, purchaseCount = 0;
    const byProduct = {};
    const byMethod = {};
    for (const r of rows) {
      if (r.type === 'recharge') { rechargeTotal += r.amount_centimes; rechargeCount++; byMethod[r.method || 'other'] = (byMethod[r.method || 'other'] || 0) + r.amount_centimes; }
      else if (r.type === 'purchase') {
        purchaseTotal += -r.amount_centimes; purchaseCount++;
        const k = r.product_name || r.product_id || '—';
        byProduct[k] = byProduct[k] || { name: k, count: 0, totalCentimes: 0 };
        byProduct[k].count++; byProduct[k].totalCentimes += -r.amount_centimes;
      } else if (r.type === 'refund') { refundTotal += r.amount_centimes; }
    }
    res.json({
      date, currency: CURRENCY,
      rechargeTotalCentimes: rechargeTotal, rechargeCount,
      purchaseTotalCentimes: purchaseTotal, purchaseCount,
      refundTotalCentimes: refundTotal,
      rechargeByMethod: byMethod,
      products: Object.values(byProduct).sort((a, b) => b.totalCentimes - a.totalCentimes),
    });
  });

  // ── Nightly integrity job: re-SUM the ledger vs materialized balances ────────
  const reconcile = () => {
    try {
      // Cover BOTH balance rows and any member that has ledger rows without a balance row.
      const drift = sdb.prepare(`
        SELECT m.member_id,
               COALESCE(b.balance_centimes, 0) AS stored,
               COALESCE(t.summed, 0) AS summed
        FROM (SELECT member_id FROM wallet_balances
              UNION SELECT DISTINCT member_id FROM wallet_transactions) m
        LEFT JOIN wallet_balances b ON b.member_id = m.member_id
        LEFT JOIN (SELECT member_id, SUM(amount_centimes) AS summed FROM wallet_transactions GROUP BY member_id) t
               ON t.member_id = m.member_id
      `).all().filter((r) => r.stored !== r.summed);
      if (drift.length) console.error('🚨 WALLET LEDGER DRIFT DETECTED:', JSON.stringify(drift));
      else console.log('✅ Wallet ledger reconciliation OK');
    } catch (e) { console.error('Wallet reconciliation failed:', e.message); }
  };
  setInterval(reconcile, 24 * 60 * 60 * 1000).unref?.();

  return router;
};
