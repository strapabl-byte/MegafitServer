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
    user_id     TEXT,            -- ZKTeco machine user ID (new format: [1234] John Doe)
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
    subscription_name TEXT,
    expires_on  TEXT,
    period_from TEXT,
    status      TEXT,
    birthday    TEXT,
    cin         TEXT,
    qr_token    TEXT,
    photo       TEXT,
    pdf_url     TEXT,
    synced_at   TEXT,
    balance     REAL DEFAULT 0,
    created_at  TEXT,
    total_paid  REAL DEFAULT 0,
    last_payment_date TEXT,
    email       TEXT,
    adresse     TEXT,
    ville       TEXT,
    is_archive  INTEGER DEFAULT 0,
    bonus_3months INTEGER DEFAULT 0,
    inscription_id TEXT,
    balance_deadline TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_members_gym ON members_cache(gym_id);
`);

// ── Migrations for existing tables (Render disk persistence) ─────────────────
// These run every startup but only ADD if column is missing.
const migrations = [
  'ALTER TABLE members_cache ADD COLUMN email TEXT',
  'ALTER TABLE members_cache ADD COLUMN adresse TEXT',
  'ALTER TABLE members_cache ADD COLUMN ville TEXT',
  'ALTER TABLE members_cache ADD COLUMN is_archive INTEGER DEFAULT 0',
  'ALTER TABLE members_cache ADD COLUMN bonus_3months INTEGER DEFAULT 0',
  'ALTER TABLE members_cache ADD COLUMN inscription_id TEXT'
];

for (const m of migrations) {
  try { db.prepare(m).run(); } catch (e) { /* column already exists */ }
}

db.exec(`
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
    status      TEXT DEFAULT 'approved',
    requested_by TEXT,
    approved_by  TEXT,
    created_at  TEXT,
    synced_at   TEXT,
    PRIMARY KEY (id, gym_id)
  );
  CREATE INDEX IF NOT EXISTS idx_decaissements_gym_date ON decaissements_cache(gym_id, date);

  -- ─── ODOO Members Reference (loaded from slim JSON on startup) ───────────
  CREATE TABLE IF NOT EXISTS odoo_members_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name   TEXT NOT NULL,
    first_name  TEXT,
    last_name   TEXT,
    gym_id      TEXT NOT NULL,
    status      TEXT DEFAULT 'Active',
    expires_on  TEXT,
    name_norm   TEXT  -- pre-normalized for fast fuzzy matching
  );
  CREATE INDEX IF NOT EXISTS idx_odoo_members_norm  ON odoo_members_cache(name_norm);
  CREATE INDEX IF NOT EXISTS idx_odoo_members_gym   ON odoo_members_cache(gym_id);

  -- ─── Smart Identity Cache (Groq + fuzzy results, persist on Render disk) ─
  CREATE TABLE IF NOT EXISTS smart_identity_cache (
    entry_key     TEXT PRIMARY KEY,   -- user_id (preferred) or normalized name
    gym_id        TEXT,
    matched_name  TEXT,
    matched_gym   TEXT,
    id_status     TEXT DEFAULT 'unknown', -- confirmed|probable|wrong_gym|expired|unknown|pending
    confidence    INTEGER DEFAULT 0,
    comment       TEXT,
    groq_used     INTEGER DEFAULT 0,
    cached_at     TEXT
  );

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
    pdf_url TEXT,
    cheque_photo TEXT,
    cheque_photo_back TEXT
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

  CREATE TABLE IF NOT EXISTS kids_courses (
    id          TEXT PRIMARY KEY,
    gym_id      TEXT NOT NULL DEFAULT 'dokarat',
    group_id    TEXT NOT NULL,   -- A, B, C, D, E
    group_name  TEXT NOT NULL,
    day         TEXT NOT NULL,
    time_start  TEXT NOT NULL,
    time_end    TEXT NOT NULL,
    activity    TEXT NOT NULL,  -- Natation | Funfit
    ages        TEXT NOT NULL,
    created_at  TEXT,
    updated_at  TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_kids_gym ON kids_courses(gym_id);

  CREATE TABLE IF NOT EXISTS recruitment_applications (
    id          TEXT PRIMARY KEY,
    fullName    TEXT,
    email       TEXT,
    phone       TEXT,
    position    TEXT,
    motivation  TEXT,
    cvLink      TEXT,
    status      TEXT DEFAULT 'new',
    createdAt   TEXT,
    synced_at   TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_recruitment_date ON recruitment_applications(createdAt);
`);

// ── Migrations ──────────────────────────────────────────────────────────────
try { db.prepare("ALTER TABLE pending_cache ADD COLUMN status TEXT DEFAULT 'pending'").run(); } catch(e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN pdf_url TEXT;"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE members_cache ADD COLUMN balance REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN created_at TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN subscription_name TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN cin TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN period_from TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN total_paid REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN last_payment_date TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN is_archive INTEGER DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN contract_number TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN cheque_photo TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE members_cache ADD COLUMN cheque_photo_back TEXT;"); } catch (e) {}
// register_cache extensions
try { db.exec("ALTER TABLE register_cache ADD COLUMN cin TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN tel TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN prix REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN reste REAL DEFAULT 0;"); } catch (e) {}
try { db.exec("ALTER TABLE register_cache ADD COLUMN note_reste TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN pdf_url TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN totals TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN payments TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN cin TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN adresse TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN ville TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN email TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN commercial TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN contract_number TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN period_from TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN period_to TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN telephone TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN date_naissance TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN profile_picture TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN cheque_photo TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE pending_cache ADD COLUMN cheque_photo_back TEXT;"); } catch (e) {}
try { db.exec(`
  CREATE TABLE IF NOT EXISTS incidents_cache (
    id TEXT PRIMARY KEY, gym_id TEXT, gym_name TEXT, title TEXT, cause TEXT,
    explanation TEXT, emergency TEXT, status TEXT DEFAULT 'Pending',
    reporter TEXT, date TEXT, created_at TEXT, synced_at TEXT
  );
`); } catch (e) {}
try { db.exec("ALTER TABLE decaissements_cache ADD COLUMN status TEXT DEFAULT 'approved';"); } catch (e) {}
try { db.exec("ALTER TABLE decaissements_cache ADD COLUMN requested_by TEXT;"); } catch (e) {}
try { db.exec("ALTER TABLE decaissements_cache ADD COLUMN approved_by TEXT;"); } catch (e) {}

// ── ReSubIntelligence Cache — persists AI+fuzzy verdicts to avoid re-running Groq ──
try { db.exec(`
  CREATE TABLE IF NOT EXISTS resub_intelligence_cache (
    register_id   TEXT NOT NULL,
    gym_id        TEXT NOT NULL,
    nom_key       TEXT NOT NULL,           -- cleanedNom (normalized)
    type          TEXT NOT NULL,           -- NEW | RESUB | POSSIBLE
    confidence    INTEGER DEFAULT 0,
    matched_name  TEXT,
    prev_club     TEXT,
    prev_gym_id   TEXT,
    prev_status   TEXT,
    last_sub      TEXT,
    ai_verified   INTEGER DEFAULT 0,       -- 1 if Groq confirmed
    ai_reason     TEXT,
    detection_mode TEXT DEFAULT 'FUZZY',   -- FUZZY | AI+FUZZY
    used_variant  TEXT,                    -- what name was actually matched
    was_split     INTEGER DEFAULT 0,       -- 1 if Moroccan name splitter was used
    cached_at     TEXT NOT NULL,           -- ISO timestamp
    PRIMARY KEY (register_id)
  );
  CREATE INDEX IF NOT EXISTS idx_resub_cache_gym ON resub_intelligence_cache(gym_id);
  CREATE INDEX IF NOT EXISTS idx_resub_cache_nom ON resub_intelligence_cache(nom_key);
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

// Safe migration: add user_id column if it doesn't exist yet (idempotent)
try { db.exec('ALTER TABLE entries ADD COLUMN user_id TEXT'); } catch(_) {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)'); } catch(_) {}

// Safe migration: add zkteco_user_id to members_cache (used to cross-ref door entries by ID)
try { db.exec('ALTER TABLE members_cache ADD COLUMN zkteco_user_id TEXT'); } catch(_) {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_members_zkteco_id ON members_cache(zkteco_user_id)'); } catch(_) {}

// Safe migration: add bonus_3months to members_cache
try { db.exec('ALTER TABLE members_cache ADD COLUMN bonus_3months INTEGER DEFAULT 0'); } catch(_) {}

// Safe migration: add balance_deadline to members_cache
try { db.exec('ALTER TABLE members_cache ADD COLUMN balance_deadline TEXT'); } catch(_) {}

const insertEntry = db.prepare(`
  INSERT OR REPLACE INTO entries (id, gym_id, date, timestamp, name, method, status, is_face, user_id)
  VALUES (@id, @gym_id, @date, @timestamp, @name, @method, @status, @is_face, @user_id)
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
    user_id:   e.user_id || null,
  })));
}

function getEntries(gymId, options = {}) {
  const { date, startDate, endDate, name, limit = 50 } = options;
  const g = buildInClause(getGymIds(gymId));
  let sql = `SELECT * FROM entries WHERE ${g.sql}`;
  let params = [...g.params];

  if (date) {
    sql += ` AND date=?`;
    params.push(date);
  } else {
    if (startDate) {
      sql += ` AND date>=?`;
      params.push(startDate);
    }
    if (endDate) {
      sql += ` AND date<=?`;
      params.push(endDate);
    }
  }

  if (name && name.trim() !== '') {
    sql += ` AND name LIKE ?`;
    params.push(`%${name.trim()}%`);
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

function getDailyStatsRange(gymId, startDate, endDate) {
  const g = buildInClause(getGymIds(gymId));
  let sql = '';
  if (getGymIds(gymId).length <= 1 && gymId !== 'all') {
    sql = `SELECT date, count, raw_count FROM daily_stats WHERE ${g.sql} AND date >= ? AND date <= ? ORDER BY date DESC`;
  } else {
    // Aggregation mode
    sql = `SELECT date, SUM(count) as count, SUM(raw_count) as raw_count 
           FROM daily_stats WHERE ${g.sql} AND date >= ? AND date <= ?
           GROUP BY date ORDER BY date DESC`;
  }
  
  const results = db.prepare(sql).all(...g.params, startDate, endDate);
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
    (id, gym_id, full_name, phone, plan, subscription_name, expires_on, period_from, status, birthday, cin, qr_token, photo, pdf_url, synced_at, balance, created_at, total_paid, last_payment_date, email, adresse, ville, is_archive, bonus_3months, inscription_id, contract_number, balance_deadline, cheque_photo, cheque_photo_back)
  VALUES
    (@id, @gym_id, @full_name, @phone, @plan, @subscription_name, @expires_on, @period_from, @status, @birthday, @cin, @qr_token, @photo, @pdf_url, @synced_at, @balance, @created_at, @total_paid, @last_payment_date, @email, @adresse, @ville, @is_archive, @bonus_3months, @inscription_id, @contract_number, @balance_deadline, @cheque_photo, @cheque_photo_back)
`);

function upsertMembers(gymId, membersArr) {
  // 🏦 CANONICAL GYMS — must match exactly what is stored in Firestore
  const CANONICAL_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];

  // Resolve the true gym_id for a member, giving priority to the member's own
  // location/gymId fields. Falls back to the caller's gymId only if unknown.
  function resolveMemberGym(m) {
    const directGymId = (m.gymId || '').toLowerCase().trim();
    if (CANONICAL_GYMS.includes(directGymId)) return directGymId;

    const loc = (m.location || '').toLowerCase().trim();
    if (!loc && CANONICAL_GYMS.includes(gymId)) return gymId;

    // Map known location strings to canonical IDs
    if (['dokkarat fes','dokkarat','doukkarate','fes dokkarat','dokarat','dukkarate'].some(s => loc.includes(s))) return 'dokarat';
    if (['fes saiss','marjane','fes marjane','saiss','fès saiss','fes-saiss'].some(s => loc.includes(s))) return 'marjane';
    if (['casa 1','casa1','anfa','casa anfa','casaanfa'].some(s => loc.includes(s)) && !loc.includes('lady')) return 'casa1';
    if (['casa 2','casa2','casa lady','lady anfa','casalady'].some(s => loc.includes(s))) return 'casa2';

    // Last resort: trust the caller's gymId
    return gymId || 'unknown';
  }

  const upsert = db.transaction((rows) => {
    // Only clear if we are doing a full sync (not a small update)
    if (rows.length > 50) {
      db.prepare('DELETE FROM members_cache WHERE gym_id=?').run(gymId);
    }
    for (const m of rows) insertMember.run(m);
  });
  const now = new Date().toISOString();
  upsert(membersArr.map(m => ({
    id:                m.id,
    gym_id:            resolveMemberGym(m),
    full_name:         m.fullName || `${m.name || ''} ${m.surname || ''}`.trim(),
    phone:             m.phone || '',
    plan:              m.plan || '',
    subscription_name: m.subscriptionName || '',
    expires_on:        m.expiresOn || '',
    period_from:       m.periodFrom || '',
    status:            m.status || '',
    birthday:          m.birthday || '',
    cin:               m.cin || '',
    qr_token:          m.qrToken || '',
    photo:             m.photo || m.image || null,
    pdf_url:           m.pdfUrl || null,
    synced_at:         now,
    balance:           Number(m.balance) || 0,
    created_at:        typeof m.createdAt === 'string' ? m.createdAt :
                       (m.createdAt && typeof m.createdAt.toDate === 'function') ? m.createdAt.toDate().toISOString() :
                       (m.createdAt?._seconds ? new Date(m.createdAt._seconds * 1000).toISOString() :
                       (m.createdAt?.toISOString ? m.createdAt.toISOString() : null)),
    total_paid:        Number(m.totalPaid || m.total_paid) || 0,
    last_payment_date: m.lastPaymentDate || m.last_payment_date || null,
    email:             m.email || '',
    adresse:           m.adresse || '',
    ville:             m.ville || '',
    is_archive:        (m.isArchive || m.is_archive || m.importedFromOdoo) ? 1 : 0,
    bonus_3months:     m.bonus3Months ? 1 : 0,
    inscription_id:    m.inscriptionId || m.inscription_id || null,
    contract_number:   m.contractNumber || m.contract_number || null,
    balance_deadline:  m.balanceDeadline || m.balance_deadline || null,
    cheque_photo:      m.chequePhoto || m.cheque_photo || null,
    cheque_photo_back: m.chequePhotoBack || m.cheque_photo_back || m.chequePhotoVerso || null,
  })));
}

function getMembers(gymId) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT * FROM members_cache WHERE ${g.sql} AND is_archive = 0 ORDER BY created_at DESC, full_name ASC`;
  return db.prepare(sql).all(...g.params);
}

function getDebtors(gymId) {
  const g = buildInClause(getGymIds(gymId));
  // Order: overdue first (deadline in past), then by deadline ASC, then by balance DESC
  const sql = `
    SELECT * FROM members_cache 
    WHERE ${g.sql} AND balance > 0 AND is_archive = 0 
    ORDER BY 
      CASE WHEN balance_deadline IS NOT NULL AND balance_deadline < date('now') THEN 0 ELSE 1 END ASC,
      balance_deadline ASC NULLS LAST,
      balance DESC
  `;
  return db.prepare(sql).all(...g.params);
}

function pruneStaleMember(memberId) {
  db.prepare('DELETE FROM members_cache WHERE id=?').run(memberId);
}

// Lookup a single member by Firebase ID from the disk
function getMemberById(memberId) {
  return db.prepare('SELECT * FROM members_cache WHERE id=? LIMIT 1').get(memberId) || null;
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
               typeof e.created_at === 'string' ? e.created_at :
               (e.createdAt && typeof e.createdAt.toDate === 'function') ? e.createdAt.toDate().toISOString() :
               (e.createdAt?.toISOString ? e.createdAt.toISOString() : now),
    synced_at:  now
  })));
}

function getRegister(gymId, date) {
  const g = buildInClause(getGymIds(gymId));
  const sql = `SELECT * FROM register_cache WHERE ${g.sql} AND date=? ORDER BY created_at DESC`;
  return db.prepare(sql).all(...g.params, date);
}

function deleteRegisterEntry(gymId, date, entryId) {
  db.prepare('DELETE FROM register_cache WHERE id=? AND gym_id=? AND date=?').run(entryId, gymId, date);
}

// ── DÉCAISSEMENTS ────────────────────────────────────────────────────────────

const insertDecaissement = db.prepare(`
  INSERT OR REPLACE INTO decaissements_cache 
    (id, gym_id, date, montant, raison, commercial, signature, status, requested_by, approved_by, created_at, synced_at)
  VALUES 
    (@id, @gym_id, @date, @montant, @raison, @commercial, @signature, @status, @requested_by, @approved_by, @created_at, @synced_at)
`);

function upsertDecaissements(gymId, date, decsArr) {
  const upsert = db.transaction((rows) => {
    for (const d of rows) insertDecaissement.run(d);
  });
  const now = new Date().toISOString();
  upsert(decsArr.map(d => ({
    id:           d.id,
    gym_id:       gymId,
    date:         date,
    montant:      Number(d.montant) || 0,
    raison:       d.raison || '',
    commercial:   d.commercial || '',
    signature:    d.signature || '',
    status:       d.status || 'approved',
    requested_by: d.requestedBy || null,
    approved_by:  d.approvedBy || null,
    created_at: typeof d.createdAt === 'string' ? d.createdAt : 
               typeof d.created_at === 'string' ? d.created_at :
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

// ── PENDING MEMBERS (AURALIX FAST ANALYTICS) ────────────────────────────────
function setPending(data) {
  if (!data || !data.id) return;
  try {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO pending_cache 
      (id, gym_id, date, nom, prenom, subscriptionName, total, paid, balance, status, pdf_url, totals, payments, cin, adresse, ville, email, commercial, contract_number, period_from, period_to, telephone, date_naissance, profile_picture, cheque_photo, cheque_photo_back)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const ts = data.createdAt
      ? (data.createdAt._seconds ? new Date(data.createdAt._seconds * 1000) : new Date(data.createdAt))
      : new Date();
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
      data.pdfUrl || data.pdf_url || null,
      data.totals ? JSON.stringify(data.totals) : null,
      data.payments ? JSON.stringify(data.payments) : null,
      data.cin || null,
      data.adresse || null,
      data.ville || null,
      data.email || null,
      data.commercial || null,
      data.contractNumber || null,
      data.periodFrom || null,
      data.periodTo || null,
      data.telephone || null,
      data.dateNaissance || null,
      data.profilePicture || data.profile_picture || null,
      data.chequePhoto || data.cheque_photo || null,
      data.chequePhotoVerso || data.cheque_photo_back || null
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

function updatePendingChequePhotos(id, chequePhoto, chequePhotoBack) {
  if (!id) return;
  try {
    db.prepare(`UPDATE pending_cache SET cheque_photo = ?, cheque_photo_back = ? WHERE id = ?`).run(chequePhoto, chequePhotoBack, id);
  } catch(err) {
    console.error('SQLite updatePendingChequePhotos error:', err.message);
  }
}

function updateMemberChequePhotos(id, chequePhoto, chequePhotoBack) {
  if (!id) return;
  try {
    db.prepare(`UPDATE members_cache SET cheque_photo = ?, cheque_photo_back = ? WHERE id = ?`).run(chequePhoto, chequePhotoBack, id);
  } catch(err) {
    console.error('SQLite updateMemberChequePhotos error:', err.message);
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

// Lookup a single pending inscription by its Firebase ID
function getPendingById(inscriptionId) {
  try {
    return db.prepare('SELECT * FROM pending_cache WHERE id = ? LIMIT 1').get(inscriptionId) || null;
  } catch(err) {
    return null;
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

// ── KIDS COURSES ──────────────────────────────────────────────────────────────────────

const { randomUUID } = require('crypto');

function upsertKidsCourse(course) {
  const now = new Date().toISOString();
  const id  = course.id || randomUUID();
  db.prepare(`
    INSERT OR REPLACE INTO kids_courses
    (id, gym_id, group_id, group_name, day, time_start, time_end, activity, ages, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM kids_courses WHERE id=?), ?), ?)
  `).run(id, course.gymId || 'dokarat', course.groupId, course.groupName,
         course.day, course.timeStart, course.timeEnd, course.activity, course.ages,
         id, now, now);
  return id;
}

function getKidsCourses(gymId = 'dokarat') {
  return db.prepare(`SELECT * FROM kids_courses WHERE gym_id = ? ORDER BY group_id, day, time_start`).all(gymId);
}

function updateKidsCourse(id, fields) {
  const allowed = ['group_id','group_name','day','time_start','time_end','activity','ages'];
  const set = allowed.filter(k => fields[k] !== undefined).map(k => `${k} = ?`).join(', ');
  if (!set) return;
  const vals = allowed.filter(k => fields[k] !== undefined).map(k => fields[k]);
  db.prepare(`UPDATE kids_courses SET ${set}, updated_at = ? WHERE id = ?`)
    .run(...vals, new Date().toISOString(), id);
}

function deleteKidsCourse(id) {
  db.prepare(`DELETE FROM kids_courses WHERE id = ?`).run(id);
}

// ── RECRUITMENT ───────────────────────────────────────────────────────────────

const insertRecruitment = db.prepare(`
  INSERT OR REPLACE INTO recruitment_applications
    (id, fullName, email, phone, position, motivation, cvLink, status, createdAt, synced_at)
  VALUES
    (@id, @fullName, @email, @phone, @position, @motivation, @cvLink, @status, @createdAt, @synced_at)
`);

function upsertRecruitmentApplications(apps) {
  const now = new Date().toISOString();
  const upsert = db.transaction((rows) => {
    for (const a of rows) {
      insertRecruitment.run({
        id:         a.id,
        fullName:   a.fullName || '',
        email:      a.email || '',
        phone:      a.phone || '',
        position:   a.position || '',
        motivation: a.motivation || '',
        cvLink:     a.cvLink || '',
        status:     a.status || 'new',
        createdAt:  a.createdAt || now,
        synced_at:  now
      });
    }
  });
  upsert(apps);
}

function getRecruitmentApplications() {
  return db.prepare(`SELECT * FROM recruitment_applications ORDER BY createdAt DESC`).all();
}

function getLastRecruitmentSync() {
  return getMeta('last_recruitment_sync');
}

function setLastRecruitmentSync(ts) {
  setMeta('last_recruitment_sync', ts || new Date().toISOString());
}

// ── STATS ─────────────────────────────────────────────────────────────────────

function getCacheStats() {
  return {
    entries:  db.prepare('SELECT COUNT(*) as n FROM entries').get().n,
    members:  db.prepare('SELECT COUNT(*) as n FROM members_cache').get().n,
    payments: db.prepare('SELECT COUNT(*) as n FROM payments_cache').get().n,
    stats:    db.prepare('SELECT COUNT(*) as n FROM daily_stats').get().n,
    recruitment: db.prepare('SELECT COUNT(*) as n FROM recruitment_applications').get().n,
  };
}

module.exports = {
  // raw db — for custom queries in routes (e.g. commercial stats aggregation)
  db,
  // entries
  upsertEntries, getEntries, getEntryCount, getUniqueEntryCount,
  // daily stats
  upsertDailyStat, getDailyStats, getDailyStatsRange, getDailyStat,
  // members
  upsertMembers, getMembers, getMemberById, pruneStaleMember, getDebtors, updateMemberChequePhotos,
  // register
  upsertRegister, getRegister, deleteRegisterEntry,
  // decaissements
  upsertDecaissements, getDecaissements, deleteDecaissement,
  // payments
  upsertPayments, getPayments, deletePayment,
  // meta
  getMeta, setMeta, getLastSync, setLastSync,
  // pending (auralix)
  setPending, updatePendingStatus, updatePendingChequePhotos, getPending, getPendingWithPdf, getPendingById,
  // incidents cache
  upsertIncidents, getIncidents, resolveIncidentCache,
  // kids courses
  upsertKidsCourse, getKidsCourses, updateKidsCourse, deleteKidsCourse,
  // recruitment
  upsertRecruitmentApplications, getRecruitmentApplications, getLastRecruitmentSync, setLastRecruitmentSync,
  // info
  getCacheStats,
};

