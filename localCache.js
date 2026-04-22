// localCache.js — SQLite-backed local cache for Megafit
// Stores entries, members, payments, daily stats per gym_id
// Eliminates Firestore reads for all display data → protects Firebase quota
'use strict';

const Database = require('better-sqlite3');
const path     = require('path');

const fs       = require('fs');

// 🚀 Production Persistence: Use /var/data (Render Disk) if available, otherwise fallback to local
const DATA_DIR = fs.existsSync('/var/data') ? '/var/data' : __dirname;
const DB_PATH  = path.join(DATA_DIR, 'megafit_cache.db');

console.log(`📡 SQLite database target: ${DB_PATH}`);
const db = new Database(DB_PATH);

// ── Performance pragmas ─────────────────────────────────────────────────────
db.pragma('journal_mode = WAL');   // concurrent reads + writes
db.pragma('synchronous = NORMAL'); // safe + fast

// ── Schema ──────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS entries (
    id          TEXT,
    gym_id      TEXT NOT NULL,
    date        TEXT NOT NULL,   -- YYYY-MM-DD
    timestamp   TEXT NOT NULL,   -- full ISO string
    name        TEXT,
    method      TEXT,
    status      TEXT,
    is_face     INTEGER DEFAULT 0,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_entries_gym_date ON entries(gym_id, date);

  CREATE TABLE IF NOT EXISTS daily_stats (
    gym_id      TEXT NOT NULL,
    date        TEXT NOT NULL,   -- YYYY-MM-DD
    count       INTEGER DEFAULT 0,
    raw_count   INTEGER DEFAULT 0,
    synced_at   TEXT,
    PRIMARY KEY (gym_id, date)
  );

  CREATE TABLE IF NOT EXISTS members_cache (
    id          TEXT NOT NULL,
    gym_id      TEXT NOT NULL,
    full_name   TEXT,
    phone       TEXT,
    plan        TEXT,
    expires_on  TEXT,
    status      TEXT,
    birthday    TEXT,
    qr_token    TEXT,
    photo       TEXT,
    pdf_url     TEXT,
    synced_at   TEXT,
    balance     REAL DEFAULT 0,
    created_at  TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_members_gym ON members_cache(gym_id);

  CREATE TABLE IF NOT EXISTS register_cache (
    id          TEXT NOT NULL,
    gym_id      TEXT NOT NULL,
    date        TEXT NOT NULL,
    nom         TEXT,
    contrat     TEXT,
    commercial  TEXT,
    tpe         REAL DEFAULT 0,
    espece      REAL DEFAULT 0,
    virement    REAL DEFAULT 0,
    cheque      REAL DEFAULT 0,
    abonnement  TEXT,
    created_at  TEXT,
    synced_at   TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_register_gym_date ON register_cache(gym_id, date);

  CREATE TABLE IF NOT EXISTS payments_cache (
    id          TEXT NOT NULL,
    gym_id      TEXT NOT NULL,
    member_name TEXT,
    amount      REAL DEFAULT 0,
    method      TEXT,
    date        TEXT,
    plan        TEXT,
    synced_at   TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_payments_gym ON payments_cache(gym_id);

  CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT
  );
  CREATE TABLE IF NOT EXISTS decaissements_cache (
    id          TEXT NOT NULL,
    gym_id      TEXT NOT NULL,
    date        TEXT NOT NULL,
    montant     REAL DEFAULT 0,
    raison      TEXT,
    commercial  TEXT,
    signature   TEXT,
    created_at  TEXT,
    synced_at   TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_decaissements_gym_date ON decaissements_cache(gym_id, date);

  CREATE TABLE IF NOT EXISTS pending_cache (
    id TEXT PRIMARY KEY,
    gym_id TEXT,
    date TEXT,
    nom TEXT,
    prenom TEXT,
    subscriptionName TEXT,
    total REAL,
    paid REAL,
    balance REAL,
    status TEXT DEFAULT 'pending',
    pdf_url TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_pending_gym_date ON pending_cache(gym_id, date);

  CREATE TABLE IF NOT EXISTS incidents_cache (
    id          TEXT PRIMARY KEY,
    gym_id      TEXT,
    gym_name    TEXT,
    title       TEXT,
    cause       TEXT,
    explanation TEXT,
    emergency   TEXT,
    status      TEXT DEFAULT 'Pending',
    reporter    TEXT,
    date        TEXT,
    created_at  TEXT,
    synced_at   TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_incidents_gym ON incidents_cache(gym_id, status);
`);

// ── Migrations ──────────────────────────────────────────────────────────────
try { db.prepare("ALTER TABLE pending_cache ADD COLUMN status TEXT DEFAULT 'pending'").run(); } catch(e) {}
try {
  db.exec("ALTER TABLE members_cache ADD COLUMN pdf_url TEXT;");
} catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE members_cache ADD COLUMN balance REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN cin TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN tel TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN prix REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN reste REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN note_reste TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN created_at TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN pdf_url TEXT;"); } catch (e) {}
try { db.exec(`
  CREATE TABLE IF NOT EXISTS incidents_cache (
    id TEXT PRIMARY KEY, gym_id TEXT, gym_name TEXT, title TEXT, cause TEXT,
    explanation TEXT, emergency TEXT, status TEXT DEFAULT 'Pending',
    reporter TEXT, date TEXT, created_at TEXT, synced_at TEXT
  );
`); } catch (e) {}


console.log(`💾 SQLite cache initialised → ${DB_PATH}`);

// ── HELPERS ──────────────────────────────────────────────────────────────────

function getGymIds(gymId) {
  if (!gymId || gymId === 'all') return [];
  if (Array.isArray(gymId)) return gymId;
  return String(gymId).split(',').map(s => s.trim()).filter(Boolean);
}

function buildInClause(gymIds, prefix = 'gym_id') {
  if (gymIds.length === 0) return { sql: '1=1', params: [] }; // match all if empty
  const placeholders = gymIds.map(() => '?').join(',');
  return { sql: `${prefix} IN (${placeholders})`, params: gymIds };
}

// ── ENTRIES ─────────────────────────────────────────────────────────────────

const insertEntry = db.prepare(`
  INSERT OR REPLACE INTO entries (id, gym_id, date, timestamp, name, method, status, is_face)
  VALUES (@id, @gym_id, @date, @timestamp, @name, @method, @status, @is_face)
`);

function upsertEntries(gymId, entriesArr) {
  const upsert = db.transaction((rows) => {
    for (const e of rows) insertEntry.run(e);
  });
  upsert(entriesArr.map(e => ({
    id:        e.docId || e.id || `${gymId}_${e.timestamp}`,
    gym_id:    gymId,
    date:      (e.timestamp || '').slice(0, 10),
    timestamp: e.timestamp || e.displayTime || '',
    name:      e.name || '',
    method:    e.method || '',
    status:    e.status || '',
    is_face:   e.isFace ? 1 : 0,
  })));
}

function getEntries(gymId, date, limit = 50) {
  const g = buildInClause(getGymIds(gymId));
  let sql = `SELECT * FROM entries WHERE ${g.sql}`;
  let params = [...g.params];

  if (date) {
    sql += ` AND date=?`;
    params.push(date);
  }

  sql += ` ORDER BY timestamp DESC LIMIT ?`;
  params.push(limit);

  return db.prepare(sql).all(...params);
}

function getEntryCount(gymId, date) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT COUNT(*) as cnt FROM entries WHERE ${g.sql} AND date=?`;
  const row = db.prepare(sql).get(...g.params, date);
  return row?.cnt || 0;
}

function getUniqueEntryCount(gymId, date) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT COUNT(DISTINCT name) as cnt FROM entries WHERE ${g.sql} AND date=? AND name != ''`;
  const row = db.prepare(sql).get(...g.params, date);
  return row?.cnt || 0;
}

// ── DAILY STATS ──────────────────────────────────────────────────────────────

const insertStat = db.prepare(`
  INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count, synced_at)
  VALUES (@gym_id, @date, @count, @raw_count, @synced_at)
`);

function upsertDailyStat(gymId, date, count, rawCount) {
  insertStat.run({ gym_id: gymId, date, count, raw_count: rawCount, synced_at: new Date().toISOString() });
}

function getDailyStats(gymId, days = 30) {
  const g = buildInClause(getGymIds(gymId));
  let sql = '';
  if (getGymIds(gymId).length <= 1 && gymId !== 'all') {
    sql = `SELECT date, count, raw_count FROM daily_stats WHERE ${g.sql} ORDER BY date DESC LIMIT ?`;
  } else {
    // Aggregation mode
    sql = `SELECT date, SUM(count) as count, SUM(raw_count) as raw_count 
           FROM daily_stats WHERE ${g.sql} 
           GROUP BY date ORDER BY date DESC LIMIT ?`;
  }
  
  const results = db.prepare(sql).all(...g.params, days);
  return results.map(r => ({ date: r.date, count: r.count, rawCount: r.raw_count }));
}

function getDailyStat(gymId, date) {
  const g = buildInClause(getGymIds(gymId));
  if (getGymIds(gymId).length <= 1 && gymId !== 'all') {
    return db.prepare(`SELECT * FROM daily_stats WHERE ${g.sql} AND date=?`).get(...g.params, date);
  }
  // Aggregated
  return db.prepare(`SELECT SUM(count) as count, SUM(raw_count) as raw_count FROM daily_stats WHERE ${g.sql} AND date=?`).get(...g.params, date);
}

// ── MEMBERS ──────────────────────────────────────────────────────────────────

const insertMember = db.prepare(`
  INSERT OR REPLACE INTO members_cache
    (id, gym_id, full_name, phone, plan, expires_on, status, birthday, qr_token, photo, pdf_url, synced_at, balance, created_at)
  VALUES
    (@id, @gym_id, @full_name, @phone, @plan, @expires_on, @status, @birthday, @qr_token, @photo, @pdf_url, @synced_at, @balance, @created_at)
`);

function upsertMembers(gymId, membersArr) {
  const upsert = db.transaction((rows) => {
    // Only clear if we are doing a full sync (not a small update)
    if (rows.length > 50) {
      db.prepare('DELETE FROM members_cache WHERE gym_id=?').run(gymId);
    }
    for (const m of rows) insertMember.run(m);
  });
  const now = new Date().toISOString();
  upsert(membersArr.map(m => ({
    id:         m.id,
    gym_id:     gymId || m.location || m.gymId || 'unknown',
    full_name:  m.fullName || `${m.name || ''} ${m.surname || ''}`.trim(),
    phone:      m.phone || '',
    plan:       m.plan || '',
    expires_on: m.expiresOn || '',
    status:     m.status || '',
    birthday:   m.birthday || '',
    qr_token:   m.qrToken || '',
    photo:      m.photo || m.image || null,
    pdf_url:    m.pdfUrl || null,
    synced_at:  now,
    balance:    Number(m.balance) || 0,
    created_at: typeof m.createdAt === 'string' ? m.createdAt : 
               (m.createdAt && typeof m.createdAt.toDate === 'function') ? m.createdAt.toDate().toISOString() :
               (m.createdAt?._seconds ? new Date(m.createdAt._seconds * 1000).toISOString() :
               (m.createdAt?.toISOString ? m.createdAt.toISOString() : null)),
  })));
}

function getMembers(gymId) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT * FROM members_cache WHERE ${g.sql} ORDER BY full_name`;
  return db.prepare(sql).all(...g.params);
}

function pruneStaleMember(memberId) {
  db.prepare('DELETE FROM members_cache WHERE id=?').run(memberId);
}

// ── REGISTER ─────────────────────────────────────────────────────────────────

const insertRegister = db.prepare(`
  INSERT OR REPLACE INTO register_cache 
    (id, gym_id, date, nom, cin, tel, contrat, commercial, prix, tpe, espece, virement, cheque, reste, note_reste, abonnement, created_at, synced_at)
  VALUES 
    (@id, @gym_id, @date, @nom, @cin, @tel, @contrat, @commercial, @prix, @tpe, @espece, @virement, @cheque, @reste, @note_reste, @abonnement, @created_at, @synced_at)
`);

function upsertRegister(gymId, date, entriesArr) {
  const upsert = db.transaction((rows) => {
    // We don't delete everything, so we can keep partial data if sync fails
    for (const e of rows) insertRegister.run(e);
  });
  const now = new Date().toISOString();
  upsert(entriesArr.map(e => ({
    id:         e.id,
    gym_id:     gymId,
    date:       date,
    nom:        e.nom || '',
    cin:        e.cin || '',
    tel:        e.tel || '',
    contrat:    e.contrat || '',
    commercial: e.commercial || '',
    prix:       Number(e.prix) || 0,
    tpe:        Number(e.tpe) || 0,
    espece:     Number(e.espece) || 0,
    virement:   Number(e.virement) || 0,
    cheque:     Number(e.cheque) || 0,
    reste:      Number(e.reste) || 0,
    note_reste: e.note_reste || '',
    abonnement: e.abonnement || '',
    created_at: typeof e.createdAt === 'string' ? e.createdAt : 
               (e.createdAt && typeof e.createdAt.toDate === 'function') ? e.createdAt.toDate().toISOString() :
               (e.createdAt?.toISOString ? e.createdAt.toISOString() : now),
    synced_at:  now
  })));
}

function getRegister(gymId, date) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT * FROM register_cache WHERE ${g.sql} AND date=? ORDER BY created_at ASC`;
  return db.prepare(sql).all(...g.params, date);
}

function deleteRegisterEntry(gymId, date, entryId) {
  db.prepare('DELETE FROM register_cache WHERE id=? AND gym_id=? AND date=?').run(entryId, gymId, date);
}

// ── DÉCAISSEMENTS ────────────────────────────────────────────────────────────

const insertDecaissement = db.prepare(`
  INSERT OR REPLACE INTO decaissements_cache 
    (id, gym_id, date, montant, raison, commercial, signature, created_at, synced_at)
  VALUES 
    (@id, @gym_id, @date, @montant, @raison, @commercial, @signature, @created_at, @synced_at)
`);

function upsertDecaissements(gymId, date, decsArr) {
  const upsert = db.transaction((rows) => {
    for (const d of rows) insertDecaissement.run(d);
  });
  const now = new Date().toISOString();
  upsert(decsArr.map(d => ({
    id:         d.id,
    gym_id:     gymId,
    date:       date,
    montant:    Number(d.montant) || 0,
    raison:     d.raison || '',
    commercial: d.commercial || '',
    signature:  d.signature || '',
    created_at: typeof d.createdAt === 'string' ? d.createdAt : 
               (d.createdAt && typeof d.createdAt.toDate === 'function') ? d.createdAt.toDate().toISOString() :
               (d.createdAt?.toISOString ? d.createdAt.toISOString() : now),
    synced_at:  now
  })));
}

function getDecaissements(gymId, date) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT * FROM decaissements_cache WHERE ${g.sql} AND date=? ORDER BY created_at ASC`;
  return db.prepare(sql).all(...g.params, date);
}

function deleteDecaissement(gymId, date, id) {
  db.prepare('DELETE FROM decaissements_cache WHERE id=? AND gym_id=? AND date=?').run(id, gymId, date);
}

// ── PAYMENTS ─────────────────────────────────────────────────────────────────

const insertPayment = db.prepare(`
  INSERT OR REPLACE INTO payments_cache (id, gym_id, member_name, amount, method, date, plan, synced_at)
  VALUES (@id, @gym_id, @member_name, @amount, @method, @date, @plan, @synced_at)
`);

function upsertPayments(gymId, paymentsArr) {
  const upsert = db.transaction((rows) => {
    for (const p of rows) insertPayment.run(p);
  });
  const now = new Date().toISOString();
  upsert(paymentsArr.map(p => ({
    id:          p.id,
    gym_id:      gymId,
    member_name: p.memberName || p.fullName || '',
    amount:      p.amount || 0,
    method:      p.method || '',
    date:        p.date || '',
    plan:        p.plan || '',
    synced_at:   now,
  })));
}

function getPayments(gymId, limit = 200) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT * FROM payments_cache WHERE ${g.sql} ORDER BY date DESC LIMIT ?`;
  return db.prepare(sql).all(...g.params, limit);
}

function deletePayment(gymId, paymentId) {
  db.prepare('DELETE FROM payments_cache WHERE id=? AND gym_id=?').run(paymentId, gymId);
}

// ── META ─────────────────────────────────────────────────────────────────────

function getMeta(key) {
  return db.prepare('SELECT value FROM meta WHERE key=?').get(key)?.value || null;
}

function setMeta(key, value) {
  db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run(key, String(value));
}

function getLastSync(gymId) {
  return getMeta(`last_full_sync_${gymId}`);
}

function setLastSync(gymId) {
  setMeta(`last_full_sync_${gymId}`, new Date().toISOString());
}

// ── PENDING MEMBERS (MEGAEYE FAST ANALYTICS) ────────────────────────────────
function setPending(data) {
  if (!data || !data.id) return;
  try {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO pending_cache 
      (id, gym_id, date, nom, prenom, subscriptionName, total, paid, balance, status, pdf_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const ts = data.createdAt ? new Date(data.createdAt._seconds * 1000) : new Date();
    const dStr = ts.toISOString().split('T')[0];
    
    stmt.run(
      data.id,
      data.gymId || '',
      dStr,
      data.nom || '',
      data.prenom || '',
      data.subscriptionName || '',
      data.totals?.total || 0,
      data.totals?.paid || 0,
      data.totals?.balance || 0,
      data.status || 'pending',
      data.pdfUrl || data.pdf_url || null
    );
  } catch (err) {
    console.error('SQLite setPending error:', err.message);
  }
}

function updatePendingStatus(id, newStatus) {
  if (!id) return;
  try {
    db.prepare(`UPDATE pending_cache SET status = ? WHERE id = ?`).run(newStatus, id);
  } catch(err) {
    console.error('SQLite updatePendingStatus error:', err.message);
  }
}

function getPending(gymId, timeFilter = 'day') {
  try {
    let dateModifier = '-1 day'; // default to last 24h
    if (timeFilter === 'week') dateModifier = '-7 days';
    
    // SQLite can do date('now', modifier)
    if (gymId && gymId !== 'all') {
      return db.prepare(`SELECT * FROM pending_cache WHERE gym_id = ? AND date >= date('now', ?) ORDER BY date DESC, id DESC LIMIT 200`).all(gymId, dateModifier);
    }
    return db.prepare(`SELECT * FROM pending_cache WHERE date >= date('now', ?) ORDER BY date DESC, id DESC LIMIT 200`).all(dateModifier);
  } catch(err) {
    return [];
  }
}

function getPendingWithPdf(gymId) {
  try {
    if (gymId && gymId !== 'all') {
      const g = buildInClause(getGymIds(gymId));
      return db.prepare(`SELECT * FROM pending_cache WHERE ${g.sql} AND pdf_url IS NOT NULL ORDER BY date DESC`).all(...g.params);
    }
    return db.prepare(`SELECT * FROM pending_cache WHERE pdf_url IS NOT NULL ORDER BY date DESC`).all();
  } catch(err) {
    return [];
  }
}

// ── INCIDENTS CACHE ───────────────────────────────────────────────────────────────────

function upsertIncidents(incidents) {
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO incidents_cache
    (id, gym_id, gym_name, title, cause, explanation, emergency, status, reporter, date, created_at, synced_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const run = db.transaction((rows) => {
    for (const r of rows) stmt.run(
      r.id, r.gymId || '', r.gymName || '', r.title || '', r.cause || '',
      r.explanation || '', r.emergency || 'Low', r.status || 'Pending',
      r.reporter || '', r.date || '', r.createdAt || now, now
    );
  });
  run(incidents);
}

function getIncidents(gymId) {
  if (gymId && gymId !== 'all') {
    const g = buildInClause(getGymIds(gymId));
    return db.prepare(`SELECT * FROM incidents_cache WHERE ${g.sql} ORDER BY created_at DESC`).all(...g.params);
  }
  return db.prepare(`SELECT * FROM incidents_cache ORDER BY created_at DESC`).all();
}

function resolveIncidentCache(id) {
  db.prepare(`UPDATE incidents_cache SET status = 'Resolved', synced_at = ? WHERE id = ?`)
    .run(new Date().toISOString(), id);
}

// ── STATS ─────────────────────────────────────────────────────────────────────

function getCacheStats() {
  return {
    entries:  db.prepare('SELECT COUNT(*) as n FROM entries').get().n,
    members:  db.prepare('SELECT COUNT(*) as n FROM members_cache').get().n,
    payments: db.prepare('SELECT COUNT(*) as n FROM payments_cache').get().n,
    stats:    db.prepare('SELECT COUNT(*) as n FROM daily_stats').get().n,
  };
}

module.exports = {
  // entries
  upsertEntries, getEntries, getEntryCount, getUniqueEntryCount,
  // daily stats
  upsertDailyStat, getDailyStats, getDailyStat,
  // members
  upsertMembers, getMembers, pruneStaleMember,
  // register
  upsertRegister, getRegister, deleteRegisterEntry,
  // decaissements
  upsertDecaissements, getDecaissements, deleteDecaissement,
  // payments
  upsertPayments, getPayments, deletePayment,
  // meta
  getMeta, setMeta, getLastSync, setLastSync,
  // pending (megaeye)
  setPending, updatePendingStatus, getPending, getPendingWithPdf,
  // incidents cache
  upsertIncidents, getIncidents, resolveIncidentCache,
  // info
  getCacheStats,
};

