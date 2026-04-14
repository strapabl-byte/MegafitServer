// localCache.js — SQLite-backed local cache for Megafit
// Stores entries, members, payments, daily stats per gym_id
// Eliminates Firestore reads for all display data → protects Firebase quota
'use strict';

const Database = require('better-sqlite3');
const path     = require('path');

// Store the DB file next to server.js (persists between Render restarts)
const DB_PATH = path.join(__dirname, 'megafit_cache.db');
const db      = new Database(DB_PATH);

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
    synced_at   TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_members_gym ON members_cache(gym_id);

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
`);

console.log(`💾 SQLite cache initialised → ${DB_PATH}`);

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
  if (date) {
    return db.prepare(
      'SELECT * FROM entries WHERE gym_id=? AND date=? ORDER BY timestamp DESC LIMIT ?'
    ).all(gymId, date, limit);
  }
  return db.prepare(
    'SELECT * FROM entries WHERE gym_id=? ORDER BY timestamp DESC LIMIT ?'
  ).all(gymId, limit);
}

function getEntryCount(gymId, date) {
  const row = db.prepare(
    'SELECT COUNT(*) as cnt FROM entries WHERE gym_id=? AND date=?'
  ).get(gymId, date);
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
  const results = db.prepare(
    'SELECT date, count, raw_count FROM daily_stats WHERE gym_id=? ORDER BY date DESC LIMIT ?'
  ).all(gymId, days);
  return results.map(r => ({ date: r.date, count: r.count, rawCount: r.raw_count }));
}

function getDailyStat(gymId, date) {
  return db.prepare(
    'SELECT * FROM daily_stats WHERE gym_id=? AND date=?'
  ).get(gymId, date);
}

// ── MEMBERS ──────────────────────────────────────────────────────────────────

const insertMember = db.prepare(`
  INSERT OR REPLACE INTO members_cache
    (id, gym_id, full_name, phone, plan, expires_on, status, birthday, qr_token, photo, synced_at)
  VALUES
    (@id, @gym_id, @full_name, @phone, @plan, @expires_on, @status, @birthday, @qr_token, @photo, @synced_at)
`);

function upsertMembers(gymId, membersArr) {
  const upsert = db.transaction((rows) => {
    // Clear stale members for this gym first
    db.prepare('DELETE FROM members_cache WHERE gym_id=?').run(gymId);
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
    photo:      null, // never cache photos in SQLite
    synced_at:  now,
  })));
}

function getMembers(gymId) {
  if (!gymId || gymId === 'all') {
    return db.prepare('SELECT * FROM members_cache ORDER BY full_name').all();
  }
  return db.prepare('SELECT * FROM members_cache WHERE gym_id=? ORDER BY full_name').all(gymId);
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
  if (!gymId || gymId === 'all') {
    return db.prepare('SELECT * FROM payments_cache ORDER BY date DESC LIMIT ?').all(limit);
  }
  return db.prepare(
    'SELECT * FROM payments_cache WHERE gym_id=? ORDER BY date DESC LIMIT ?'
  ).all(gymId, limit);
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
  upsertEntries, getEntries, getEntryCount,
  // daily stats
  upsertDailyStat, getDailyStats, getDailyStat,
  // members
  upsertMembers, getMembers,
  // payments
  upsertPayments, getPayments,
  // meta
  getMeta, setMeta, getLastSync, setLastSync,
  // info
  getCacheStats,
};
