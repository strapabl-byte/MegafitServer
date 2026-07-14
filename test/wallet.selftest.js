'use strict';
// Self-contained money-logic test for routes/wallet.js.
// Runs the wallet router against an in-memory SQLite ledger with mocked Firebase.
// No Azure/Firestore needed. Run: node test/wallet.selftest.js
//
// Covers the handoff's 7-point checklist:
//  tampered QR → 400 · same idem key → single debit · concurrent overspend →
//  exactly one succeeds · insufficient funds → 409 · deactivated product → 410 ·
//  recharge appears in ledger · (append-only enforced structurally in wallet.js).

process.env.NODE_ENV = 'test';           // non-production
process.env.ALLOW_DEMO_TOKEN = 'true';   // explicit opt-in for the demo-token admin bypass
process.env.WALLET_ENABLED = 'true';
process.env.WALLET_QR_SECRET = 'testsecret_do_not_use_in_prod';
process.env.WALLET_CURRENCY = 'MGD';

const express = require('express');
const Database = require('better-sqlite3');
const walletRouter = require('../routes/wallet');

const MEMBER = 'member_test_1';

// ── Mock deps ────────────────────────────────────────────────────────────────
const mem = new Database(':memory:');
const deps = {
  lc: { db: mem },
  admin: {
    auth: () => ({ verifyIdToken: async () => ({ uid: MEMBER }) }),
    firestore: { FieldValue: { serverTimestamp: () => 'ts' } },
  },
  db: {
    collection: () => ({
      doc: () => ({
        get: async () => ({ exists: true, data: () => ({ status: { active: true } }) }),
        set: async () => {},
      }),
    }),
  },
};

const app = express();
app.use(express.json());
app.use('/', walletRouter(deps));

let base, failures = 0, passed = 0;
const ADMIN = { Authorization: 'Bearer demo-token', 'Content-Type': 'application/json' };
const MEMBERH = { Authorization: 'Bearer member-token', 'Content-Type': 'application/json' };

const call = async (method, path, { headers = {}, body } = {}) => {
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let data = null; try { data = await res.json(); } catch {}
  return { status: res.status, data };
};
const check = (name, cond, extra = '') => { if (cond) { passed++; console.log('  ✓', name); } else { failures++; console.error('  ✗', name, extra); } };

(async () => {
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;

  // 1) Create product (café @ 15.00 Đ = 1500c)
  let r = await call('POST', '/admin/wallet/products', { headers: ADMIN, body: { name: 'Café Créatiné', priceCentimes: 1500 } });
  check('admin create product', r.status === 200 && r.data.id, JSON.stringify(r));
  const productId = r.data.id;

  // signed QR
  r = await call('POST', `/admin/wallet/products/${productId}/qr`, { headers: ADMIN });
  check('qr payload has t=megafit.pay', r.data?.payload?.t === 'megafit.pay', JSON.stringify(r.data));
  check('qr payload sig is 64 hex', /^[0-9a-f]{64}$/i.test(r.data?.payload?.sig || ''), r.data?.payload?.sig);
  const goodQr = r.data.payload;

  // 2) member balance starts 0
  r = await call('GET', '/wallet/balance', { headers: MEMBERH });
  check('member balance starts 0 (MGD)', r.status === 200 && r.data.balanceCentimes === 0 && r.data.currency === 'MGD', JSON.stringify(r.data));

  // 3) recharge 50.00 Đ (idem key R1)
  r = await call('POST', '/admin/wallet/recharge', { headers: { ...ADMIN, 'Idempotency-Key': 'R1' }, body: { memberId: MEMBER, amountCentimes: 5000, method: 'cash' } });
  check('recharge ok → balanceAfter 5000', r.status === 200 && r.data.balanceAfterCentimes === 5000, JSON.stringify(r.data));

  // recharge retry same key R1 → single credit (still 5000, not 10000)
  r = await call('POST', '/admin/wallet/recharge', { headers: { ...ADMIN, 'Idempotency-Key': 'R1' }, body: { memberId: MEMBER, amountCentimes: 5000, method: 'cash' } });
  check('recharge idem replay → still 5000', r.status === 200 && r.data.balanceAfterCentimes === 5000, JSON.stringify(r.data));

  // 4) pay requires idempotency key
  r = await call('POST', '/wallet/pay', { headers: MEMBERH, body: { qr: goodQr } });
  check('pay without Idempotency-Key → 400', r.status === 400 && r.data.error === 'IDEMPOTENCY_KEY_REQUIRED', JSON.stringify(r.data));

  // 5) tampered price (sig no longer matches) → 400 INVALID_QR
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'P_tamper' }, body: { qr: { ...goodQr, price: 1 } } });
  check('tampered price → 400 INVALID_QR', r.status === 400 && r.data.error === 'INVALID_QR', JSON.stringify(r.data));

  // tampered sig with trailing garbage (malleability guard) → 400
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'P_tamper2' }, body: { qr: { ...goodQr, sig: goodQr.sig + 'zz' } } });
  check('sig + trailing garbage → 400 INVALID_QR', r.status === 400 && r.data.error === 'INVALID_QR', JSON.stringify(r.data));

  // 6) valid pay (idem K1) → 200, debit 1500 → balance 3500
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'K1' }, body: { qr: goodQr } });
  check('valid pay → status ok, charged 1500, balanceAfter 3500', r.status === 200 && r.data.status === 'ok' && r.data.chargedCentimes === 1500 && r.data.balanceAfterCentimes === 3500 && r.data.itemName === 'Café Créatiné', JSON.stringify(r.data));

  // 7) replay same K1 → 200 identical body, single debit
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'K1' }, body: { qr: goodQr } });
  check('pay idem replay → 200 same body', r.status === 200 && r.data.balanceAfterCentimes === 3500, JSON.stringify(r.data));
  r = await call('GET', '/wallet/balance', { headers: MEMBERH });
  check('balance debited once (3500)', r.data.balanceCentimes === 3500, JSON.stringify(r.data));

  // 8) idempotency key reuse with a DIFFERENT product → 409 IDEMPOTENCY_KEY_REUSED
  let r2 = await call('POST', '/admin/wallet/products', { headers: ADMIN, body: { name: 'Barre', priceCentimes: 2000 } });
  const p2 = r2.data.id;
  const q2 = (await call('POST', `/admin/wallet/products/${p2}/qr`, { headers: ADMIN })).data.payload;
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'K1' }, body: { qr: q2 } });
  check('idem key reused for different item → 409 REUSED', r.status === 409 && r.data.error === 'IDEMPOTENCY_KEY_REUSED', JSON.stringify(r.data));

  // 9) transactions list shape
  r = await call('GET', '/wallet/transactions?limit=10', { headers: MEMBERH });
  const t0 = (r.data.transactions || [])[0];
  check('transactions newest-first has recharge+purchase', (r.data.transactions || []).some((t) => t.type === 'purchase') && (r.data.transactions || []).some((t) => t.type === 'recharge'), JSON.stringify(r.data));
  check('txn shape: itemName+amountCentimes signed', t0 && 'itemName' in t0 && typeof t0.amountCentimes === 'number', JSON.stringify(t0));

  // 10) deactivate product → pay → 410 PRODUCT_INACTIVE
  await call('PUT', `/admin/wallet/products/${productId}`, { headers: ADMIN, body: { active: false } });
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'K_inactive' }, body: { qr: goodQr } });
  check('deactivated product → 410 PRODUCT_INACTIVE', r.status === 410 && r.data.error === 'PRODUCT_INACTIVE', JSON.stringify(r.data));

  // 11) per-transaction limit: product > 500 Đ → 400 AMOUNT_TOO_LARGE
  const big = (await call('POST', '/admin/wallet/products', { headers: ADMIN, body: { name: 'Gros', priceCentimes: 60000 } })).data.id;
  const bigQr = (await call('POST', `/admin/wallet/products/${big}/qr`, { headers: ADMIN })).data.payload;
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'K_big' }, body: { qr: bigQr } });
  check('per-txn limit >500Đ → 400 AMOUNT_TOO_LARGE', r.status === 400 && r.data.error === 'AMOUNT_TOO_LARGE', JSON.stringify(r.data));

  // 12) insufficient funds: barre (2000) x2 leaves <2000, third → 409 with balanceCentimes
  await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'B1' }, body: { qr: q2 } }); // 3500→1500
  r = await call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'B2' }, body: { qr: q2 } }); // need 2000, have 1500
  check('insufficient funds → 409 with balanceCentimes', r.status === 409 && r.data.error === 'INSUFFICIENT_FUNDS' && r.data.balanceCentimes === 1500, JSON.stringify(r.data));

  // 13) concurrent overspend: reset a fresh member-scale test — top up to exactly one café,
  //     fire two concurrent pays with different keys → exactly one 200, one 409.
  await call('POST', '/admin/wallet/recharge', { headers: { ...ADMIN, 'Idempotency-Key': 'R_top' }, body: { memberId: MEMBER, amountCentimes: 500, method: 'cash' } }); // 1500→2000
  const cafe2 = (await call('POST', '/admin/wallet/products', { headers: ADMIN, body: { name: 'Café2', priceCentimes: 2000 } })).data.id;
  const cafe2Qr = (await call('POST', `/admin/wallet/products/${cafe2}/qr`, { headers: ADMIN })).data.payload;
  const [c1, c2] = await Promise.all([
    call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'C1' }, body: { qr: cafe2Qr } }),
    call('POST', '/wallet/pay', { headers: { ...MEMBERH, 'Idempotency-Key': 'C2' }, body: { qr: cafe2Qr } }),
  ]);
  const oks = [c1, c2].filter((x) => x.status === 200).length;
  const nsf = [c1, c2].filter((x) => x.status === 409 && x.data.error === 'INSUFFICIENT_FUNDS').length;
  check('concurrent overspend → exactly one succeeds', oks === 1 && nsf === 1, JSON.stringify([c1.data, c2.data]));

  // 14) ledger reconciliation: materialized balance == SUM(ledger)
  const stored = mem.prepare('SELECT balance_centimes FROM wallet_balances WHERE member_id=?').get(MEMBER).balance_centimes;
  const summed = mem.prepare('SELECT COALESCE(SUM(amount_centimes),0) s FROM wallet_transactions WHERE member_id=?').get(MEMBER).s;
  check('ledger SUM == materialized balance', stored === summed, `stored=${stored} summed=${summed}`);

  server.close();
  console.log(`\n${failures === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${passed} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('HARNESS ERROR:', e); process.exit(2); });
