'use strict';
// server.js — Entry point. Mounts routers. Nothing more.
require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const multer    = require('multer');
const crypto    = require('crypto');
const path      = require('path');
const fs        = require('fs');
const admin     = require('firebase-admin');
const lc        = require('./localCache');
const { syncGymCounts, scheduleNightlySync } = require('./auto_sync');
const { verifyAzureToken: _vat, requireAdmin } = require('./middleware/auth');

// ─────────────────────────────────────────────────────────────────────────────
// 🔒 SECURITY: INJECT_SECRET must be set as an environment variable.
// If not set, admin endpoints will refuse all requests.
// ─────────────────────────────────────────────────────────────────────────────
const INJECT_SECRET = process.env.INJECT_SECRET;
if (!INJECT_SECRET) {
  console.error('⚠️  WARNING: INJECT_SECRET env var is not set! All /admin/* endpoints are DISABLED until you set it in Render Environment Variables.');
}
const checkSecret = (req, res) => {
  if (!INJECT_SECRET) return res.status(503).json({ error: 'Admin secret not configured on server. Set INJECT_SECRET env var.' });
  const provided = req.headers['x-inject-secret'];
  if (provided !== INJECT_SECRET) return res.status(403).json({ error: 'Forbidden' });
  return null; // OK
};

// ─────────────────────────────────────────────────────────────────────────────
// App Setup
// ─────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());

// 🔒 CORS: only allow our own frontend origins
const ALLOWED_ORIGINS = [
  'https://megafitauth.web.app',
  'https://megafitauth.firebaseapp.com',
  'https://megafitserverii.onrender.com',
  'http://localhost:5173',
  'http://localhost:4000',
  'http://localhost:3000',
  // 📡 Local network testing (same WiFi)
  'http://192.168.1.143:5173',
  'http://192.168.1.143:3001',
  'http://192.168.1.143:5174',
];
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Render internal, curl with auth)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
}));

// 🔒 RATE LIMITING
app.use('/public/', rateLimit({
  windowMs: 60 * 1000, max: 60,
  message: { error: 'Too many requests, slow down.' },
  standardHeaders: true, legacyHeaders: false,
}));
app.use('/api/', rateLimit({
  windowMs: 60 * 1000, max: 300,
  message: { error: 'Too many requests, slow down.' },
  standardHeaders: true, legacyHeaders: false,
}));
app.use('/admin/', rateLimit({
  windowMs: 60 * 1000, max: 15,
  message: { error: 'Too many admin requests.' },
  standardHeaders: true, legacyHeaders: false,
}));
// Chrome Private Network Access — allows localhost:5173 to call localhost:4000
// without triggering the "Access other apps" permission dialog.
app.use((req, res, next) => {
  if (req.method === 'OPTIONS' && req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// ─────────────────────────────────────────────────────────────────────────────
// Firebase Admin Init
// ─────────────────────────────────────────────────────────────────────────────
let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try { serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT); }
  catch (err) { console.error('❌ Failed to parse FIREBASE_SERVICE_ACCOUNT JSON:', err.message); }
}

if (!serviceAccount) {
  const secretPath = '/etc/secrets/serviceAccount.json';
  const localPath  = path.join(__dirname, 'serviceAccount.json');
  if (fs.existsSync(secretPath)) {
    console.log('📂 Found serviceAccount.json in /etc/secrets/');
    serviceAccount = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
  } else if (fs.existsSync(localPath)) {
    console.log('📂 Found local serviceAccount.json');
    serviceAccount = require(localPath);
  } else {
    console.error('❌ No serviceAccount.json found');
  }
}

if (serviceAccount) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount), storageBucket: 'mega-b891d.firebasestorage.app' });
  console.log('🚀 Firebase Admin initialized.');
} else {
  console.error('💀 Firebase Admin NOT initialized.');
}

const db     = admin.firestore();
const bucket = admin.storage().bucket();

// ─────────────────────────────────────────────────────────────────────────────
// Shared State (injected into every router)
// ─────────────────────────────────────────────────────────────────────────────
const apiCache = {
  inscriptions: {}, liveEntries: {}, dailyStats: {},
  general: {}, profiles: {}, calendar: {}, kpis: {},
};

let quotaExceededUntil  = 0;
const isQuotaExceeded   = () => Date.now() < quotaExceededUntil;
const setQuotaExceeded  = () => {
  console.error('🚫 [QUOTA] Firebase quota hit. 6-hour silence mode activated.');
  quotaExceededUntil = Date.now() + (6 * 60 * 60 * 1000);
};

function getCachedOrFetch(cacheObj, key, ttlMs, fetchFn) {
  const now   = Date.now();
  const entry = cacheObj[key] || { data: null, ts: 0 };
  if (entry.data && now - entry.ts < ttlMs) {
    console.log(`⚡ [CACHE HIT] '${key}'`); return Promise.resolve(entry.data);
  }
  console.log(`🌐 [CACHE MISS] '${key}'`);
  return fetchFn().then(data => { cacheObj[key] = { data, ts: now }; return data; });
}

function invalidateCache(cacheObj, key = null) {
  if (key) { if (cacheObj[key]) delete cacheObj[key]; }
  else     { Object.keys(cacheObj).forEach(k => delete cacheObj[k]); }
}

async function uploadBase64ToStorage(base64Data, destinationPath) {
  if (!base64Data || !base64Data.startsWith('data:image')) return base64Data;
  try {
    const matches = base64Data.match(/^data:([A-Za-z-+/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) throw new Error('Format base64 invalide');
    const file = bucket.file(destinationPath);
    await file.save(Buffer.from(matches[2], 'base64'), { metadata: { contentType: matches[1] }, resumable: false });
    const [url] = await file.getSignedUrl({ action: 'read', expires: '2100-01-01' });
    return url;
  } catch (err) { console.error('❌ Storage Upload Error:', err); return base64Data; }
}

const upload = multer({ storage: multer.memoryStorage() });

// Share db/admin via app.locals (used by requireAdmin for audit logging)
app.locals.db    = db;
app.locals.admin = admin;

// ─────────────────────────────────────────────────────────────────────────────
// Shared deps object — passed to every router
// ─────────────────────────────────────────────────────────────────────────────
const deps = {
  db, admin, lc, bucket, upload,
  apiCache, isQuotaExceeded, setQuotaExceeded,
  getCachedOrFetch, invalidateCache, uploadBase64ToStorage,
  syncGymCounts,
};

// ─────────────────────────────────────────────────────────────────────────────
// Audit Logging Middleware
// ─────────────────────────────────────────────────────────────────────────────
const auditLogger = (req, res, next) => {
  res.on('finish', () => {
    // Only log successful mutations
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method) && [200, 201].includes(res.statusCode)) {
      
      const path = req.originalUrl || req.path;
      // Skip auth/config routes
      if (path.includes('/config') || path.includes('/chat')) return;
      
      let action = 'System Activity';
      
      if (path.includes('/payments')) {
        action = req.method === 'POST' ? 'Processed new payment' : 'Updated payment details';
      } else if (path.includes('/inscriptions')) {
        action = 'Added new member';
      } else if (path.includes('/members')) {
        if (req.method === 'DELETE') action = 'Deleted a member';
        else if (req.method === 'PUT' || req.method === 'PATCH') action = 'Updated member profile';
      } else if (path.includes('/register')) {
        action = 'Processed POST register addition';
      } else if (path.includes('/courses')) {
        action = 'Updated gym schedule';
      } else {
        action = `${req.method} action in ${path.split('?')[0]}`;
      }
      
      // Attempt to extract GymId based on body or query (fallback to assignedGym)
      let gymId = req.body?.gymId || req.query?.gymId || req.query?.gym || null;
      if (!gymId && req.user && req.user.assignedGyms && req.user.assignedGyms.length === 1) {
          gymId = req.user.assignedGyms[0];
      }
      if (!gymId) gymId = 'system';

      const clubs = {
           'marjane': { id: 'marjane', name: 'Marjane', color: '#3b82f6' },
           'dokarat': { id: 'dokarat', name: 'Dokarat', color: '#10b981' },
           'casa1':   { id: 'casa1', name: 'Casa 1', color: '#f59e0b' },
           'casa2':   { id: 'casa2', name: 'Casa 2', color: '#ec4899' },
           'system':  { id: 'system', name: 'System', color: '#999999' }
      };
      
      const targetClub = clubs[gymId] || clubs['system'];
      
      const payload = {
        action,
        gymId,
        club: targetClub,
        userId: req.user?.oid || 'system_id',
        userName: req.user?.name || req.user?.preferred_username || 'App System',
        path: path.split('?')[0],
        method: req.method,
        createdAt: deps.admin.firestore.FieldValue.serverTimestamp()
      };
      
      // Exclude simple sync triggers
      if (path.includes('/admin/sync')) return;

      deps.db.collection('manager_activity_logs').add(payload).catch(err => {
         console.error('Failed to log manager activity:', err);
      });
    }
  });
  next();
};
app.use(auditLogger);

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN: Export all stats and entries for 30 days
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/admin/export-all-stats', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const dateStr = thirtyDaysAgo.toISOString().slice(0, 10);
    const stats = lc.db.prepare('SELECT * FROM daily_stats WHERE date >= ?').all(dateStr);
    const entries = lc.db.prepare('SELECT * FROM entries WHERE date >= ?').all(dateStr);
    res.json({ stats, entries });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 🔒 System Stats — requires inject secret (exposes server internals)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/system-stats', _vat, requireAdmin, (req, res) => {
  try {
    const fs   = require('fs');
    const path = require('path');
    const DB_PATH = lc.db.name; // path to the SQLite file

    const fileSize = fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0;
    const sizeMB   = parseFloat((fileSize / 1024 / 1024).toFixed(2));
    const DISK_MB  = 1024; // 1GB Render disk
    const pctUsed  = parseFloat(((sizeMB / DISK_MB) * 100).toFixed(2));

    // Row counts per table
    const tables = lc.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);
    const tableCounts = {};
    let totalRows = 0;
    for (const t of tables) {
      try {
        const n = lc.db.prepare(`SELECT COUNT(*) as n FROM "${t}"`).get().n;
        tableCounts[t] = n;
        totalRows += n;
      } catch {}
    }

    // Growth estimate: ~118 MB/year based on real data
    const MB_PER_YEAR = 118;
    const yearsRemaining = parseFloat(((DISK_MB - sizeMB) / MB_PER_YEAR).toFixed(1));

    // Server uptime
    const uptimeSeconds = Math.floor(process.uptime());
    const uptimeH = Math.floor(uptimeSeconds / 3600);
    const uptimeM = Math.floor((uptimeSeconds % 3600) / 60);

    res.json({
      db: {
        sizeMB,
        totalRows,
        pctUsed,
        diskCapacityMB: DISK_MB,
        remainingMB: parseFloat((DISK_MB - sizeMB).toFixed(1)),
        yearsRemaining,
        tables: tableCounts,
      },
      server: {
        uptimeH,
        uptimeM,
        uptimeSeconds,
        nodeVersion: process.version,
        platform: process.platform,
        memUsedMB: parseFloat((process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1)),
        memTotalMB: parseFloat((process.memoryUsage().heapTotal / 1024 / 1024).toFixed(1)),
      },
      ts: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ONE-TIME: Inject daily_stats into SQLite from local export
// MUST be registered BEFORE wildcard routers — protected by INJECT_SECRET
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/inject-stats', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;
  const { daily_stats } = req.body;
  if (!Array.isArray(daily_stats)) return res.status(400).json({ error: 'daily_stats array required' });
  let inserted = 0;
  try {
    const stmt = lc.db.prepare(`
      INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count, synced_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    const run = lc.db.transaction((rows) => {
      for (const r of rows) {
        stmt.run(r.gym_id, r.date, r.count, r.raw_count, new Date().toISOString());
        inserted++;
      }
    });
    run(daily_stats);
    console.log(`✅ [inject-stats] Injected ${inserted} rows into SQLite`);
    res.json({ ok: true, inserted });
  } catch (err) {
    console.error('[inject-stats] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN: Inject register_cache rows directly from local export — ZERO Firestore reads
// Protected by INJECT_SECRET.
// POST /admin/inject-register  body: { rows: [...], wipe: { gymId, dateFrom, dateTo } }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/inject-register', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;

  const { rows, wipe } = req.body;
  if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows array required' });

  try {
    let wiped = 0;
    // Optional: wipe a date range before injecting (to remove ghosts)
    if (wipe && wipe.gymId && wipe.dateFrom && wipe.dateTo) {
      const delReg = lc.db.prepare(
        `DELETE FROM register_cache WHERE gym_id=? AND date>=? AND date<=?`
      ).run(wipe.gymId, wipe.dateFrom, wipe.dateTo);
      
      const delDec = lc.db.prepare(
        `DELETE FROM decaissements_cache WHERE gym_id=? AND date>=? AND date<=?`
      ).run(wipe.gymId, wipe.dateFrom, wipe.dateTo);
      
      wiped = delReg.changes;
      console.log(`🗑️  [inject-register] Wiped ${wiped} register rows and ${delDec.changes} decaissements for ${wipe.gymId}`);
    }

    // Insert all rows
    const stmt = lc.db.prepare(`
      INSERT OR REPLACE INTO register_cache
        (id, gym_id, date, commercial, nom, tpe, espece, virement, cheque, prix, reste, contrat, abonnement, cin, tel, note_reste, created_at)
      VALUES
        (@id, @gym_id, @date, @commercial, @nom, @tpe, @espece, @virement, @cheque, @prix, @reste, @contrat, @abonnement, @cin, @tel, @note_reste, @created_at)
    `);
    const insertMany = lc.db.transaction((rs) => { for (const r of rs) stmt.run(r); });
    insertMany(rows);

    // Compute new totals by gym
    const totals = lc.db.prepare(`
      SELECT gym_id, SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total, COUNT(*) as nb
      FROM register_cache
      WHERE id IN (${rows.map(() => '?').join(',')})
      GROUP BY gym_id
    `).all(...rows.map(r => r.id));

    console.log(`✅ [inject-register] Inserted ${rows.length} rows, wiped ${wiped} ghosts`);
    res.json({ ok: true, inserted: rows.length, wiped, totals });
  } catch (err) {
    console.error('[inject-register] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN: Inject daily_stats (door scans) directly from local/backup
// POST /admin/inject-stats  body: { stats: [{gym_id, date, count, raw_count}] }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/inject-stats', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;

  const { stats } = req.body;
  if (!Array.isArray(stats)) return res.status(400).json({ error: 'stats array required' });

  try {
    const stmt = lc.db.prepare(`
      INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count)
      VALUES (?, ?, ?, ?)
    `);
    const insertMany = lc.db.transaction((ss) => { 
      for (const s of ss) stmt.run(s.gym_id, s.date, s.count, s.raw_count); 
    });
    insertMany(stats);

    console.log(`✅ [inject-stats] Injected ${stats.length} daily stats rows`);
    res.json({ ok: true, injected: stats.length });
  } catch (err) {
    console.error('[inject-stats] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN: Fix gym_id contamination in members_cache
// POST /admin/fix-gym-isolation
// Re-reads every member from SQLite and re-classifies gym_id using canonical resolver.
// Run once after deploying the upsertMembers bug fix.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/fix-gym-isolation', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;

  try {
    const CANONICAL_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];

    // Resolves canonical gym from available hints.
    // IMPORTANT: gym_id may be corrupt! Check subscription_name FIRST as ground truth.
    function resolveGym(m) {
      // Check subscription_name first — it reflects what was filled in at registration time
      const sub = (m.subscription_name || '').toLowerCase();
      if (sub.includes('casa anfa') || sub.includes('casa-anfa') || (sub.includes('anfa') && !sub.includes('lady'))) return 'casa1';
      if (sub.includes('casa lady') || sub.includes('lady')) return 'casa2';
      if (sub.includes('marjane') || sub.includes('saiss')) return 'marjane';
      if (sub.includes('dokkarat') || sub.includes('doukkarate') || sub.includes('dokarat')) return 'dokarat';

      // subscription_name gives no hint — trust the stored gym_id if it's canonical
      const gid = (m.gym_id || '').toLowerCase().trim();
      if (CANONICAL_GYMS.includes(gid)) return gid;

      return null; // cannot determine
    }

    // Read all members that have a balance > 0 (those are the ones that could leak)
    const allMembers = lc.db.prepare('SELECT id, gym_id, subscription_name, full_name, balance FROM members_cache WHERE balance > 0').all();
    let fixed = 0, unchanged = 0, unknowns = 0;
    const fixedList = [];

    const update = lc.db.prepare('UPDATE members_cache SET gym_id=? WHERE id=? AND gym_id=?');
    const fixMany = lc.db.transaction((rows) => {
      for (const m of rows) {
        const correct = resolveGym(m);
        if (!correct) { unknowns++; continue; }
        if (correct !== m.gym_id) {
          update.run(correct, m.id, m.gym_id);
          fixedList.push({ name: m.full_name, from: m.gym_id, to: correct, balance: m.balance });
          fixed++;
        } else {
          unchanged++;
        }
      }
    });

    fixMany(allMembers);

    console.log(`✅ [fix-gym-isolation] Fixed ${fixed} members, ${unchanged} ok, ${unknowns} unknown`);
    if (fixedList.length > 0) console.log('Fixed members:', JSON.stringify(fixedList));
    res.json({ ok: true, fixed, unchanged, unknowns, total: allMembers.length, fixedList });
  } catch (err) {
    console.error('[fix-gym-isolation] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Force-reload Odoo members from slim JSON (fixes gym_id mismatches) ─
// POST /admin/reload-odoo-members
app.post('/admin/reload-odoo-members', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;
  try {
    const slimPath = path.join(__dirname, 'data', 'odoo_members_slim.json');
    if (!fs.existsSync(slimPath)) return res.status(404).json({ error: 'odoo_members_slim.json not found' });
    const members = JSON.parse(fs.readFileSync(slimPath, 'utf8'));
    const normName = s => (s || '').replace(/\s+/g, ' ').trim().toUpperCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const deleted = lc.db.prepare('DELETE FROM odoo_members_cache').run().changes;
    const insert = lc.db.prepare(`INSERT OR IGNORE INTO odoo_members_cache (full_name, first_name, last_name, gym_id, status, expires_on, name_norm) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    const tx = lc.db.transaction((rows) => { for (const m of rows) insert.run(m.fullName, m.firstName, m.lastName, m.gymId, m.status, m.expiresOn, normName(m.fullName)); });
    tx(members);
    const byGym = lc.db.prepare('SELECT gym_id, COUNT(*) as c FROM odoo_members_cache GROUP BY gym_id').all();
    const total  = lc.db.prepare('SELECT COUNT(*) as c FROM odoo_members_cache').get().c;
    console.log(`✅ [ADMIN] Odoo members reloaded: deleted ${deleted}, inserted ${members.length}. By gym:`, byGym);
    res.json({ ok: true, deleted, inserted: members.length, total, byGym });
  } catch (err) {
    console.error('[admin/reload-odoo-members] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Clear pending_cache for a gym ───────────────────────────────────
// POST /admin/clear-pending-cache  body: { gymId }
app.post('/admin/clear-pending-cache', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;

  const { gymId } = req.body;
  if (!gymId) return res.status(400).json({ error: 'gymId required' });

  try {
    const result = lc.db.prepare('DELETE FROM pending_cache WHERE gym_id = ?').run(gymId);
    res.json({ ok: true, deleted: result.changes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Inspect pending_cache for a member (diagnostic) ─────────────────
// GET /admin/inspect-pending?nom=Maazouzi  (secret in header: x-inject-secret)
app.get('/admin/inspect-pending', (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;

  const nom = (req.query.nom || '').trim();
  if (!nom) return res.status(400).json({ error: 'nom query param required' });

  try {
    // Check which columns exist in pending_cache
    const cols = lc.db.prepare("PRAGMA table_info(pending_cache)").all().map(c => c.name);
    const hasPhotoCols = cols.includes('cheque_photo');

    const rows = lc.db.prepare(`SELECT * FROM pending_cache WHERE nom LIKE ?`).all(`%${nom}%`);

    const result = rows.map(r => ({
      id:               r.id,
      gym_id:           r.gym_id,
      nom:              r.nom,
      prenom:           r.prenom,
      date:             r.date,
      status:           r.status,
      payments:         r.payments,
      has_cheque_photo_col: hasPhotoCols,
      cheque_photo:     hasPhotoCols ? (r.cheque_photo ? `✅ YES (${Math.round((r.cheque_photo.length)/1024)}KB)` : '❌ null') : '⚠️ column missing',
      cheque_photo_back:hasPhotoCols ? (r.cheque_photo_back ? `✅ YES (${Math.round((r.cheque_photo_back.length)/1024)}KB)` : '❌ null') : '⚠️ column missing',
      profile_picture:  r.profile_picture ? `✅ YES (${Math.round((r.profile_picture.length)/1024)}KB)` : '❌ null',
      pdf_url:          r.pdf_url || null,
      all_columns:      cols,
    }));

    res.json({ found: result.length, rows: result });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN: Fix missing member balances (ONE-TIME ONLY)
// POST /admin/fix-member-balances
// ── Strategy (quota-safe):
//   1. Check SQLite meta — if already ran, return immediately (zero Firebase reads)
//   2. Read ONLY from local SQLite pending_cache to find inscriptions with balance > 0
//   3. For each, fetch ONE Firebase inscription doc to get the memberId
//   4. Check ONE Firebase member doc — skip if deleted, skip if balance already correct
//   5. Fix balance in Firebase + SQLite for affected members only
//   6. Write meta flag — endpoint becomes a no-op forever after
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/fix-member-balances', async (req, res) => {
  const fail = checkSecret(req, res); if (fail !== null) return;

  // ── ONE-TIME GUARD: Check if already done ──────────────────────────────────
  const alreadyDone = lc.getMeta('balance_fix_done');
  if (alreadyDone && req.query.force !== 'true') {
    return res.json({ ok: true, alreadyDone: true, ranAt: alreadyDone, message: 'Already ran. Pass ?force=true to re-run.' });
  }

  try {
    // ── STEP 1: Use SQLite to find ONLY inscriptions with outstanding balance ──
    // Zero Firebase reads at this stage.
    const pendingWithBalance = lc.db.prepare(`
      SELECT id, gym_id, nom, prenom, balance, paid, status 
      FROM pending_cache 
      WHERE balance > 0 
        AND status IN ('awaiting_payment', 'converted', 'pending')
      ORDER BY balance DESC
    `).all();

    console.log(`[fix-balances] Found ${pendingWithBalance.length} inscriptions with balance > 0 in SQLite`);

    const fixed   = [];
    const skipped = [];
    const errors  = [];

    // Pre-load deleted member IDs to avoid repeated Firebase reads
    const deletedSnap = await db.collection('deleted_members').select().get();
    const deletedIds  = new Set(deletedSnap.docs.map(d => d.id));
    console.log(`[fix-balances] ${deletedIds.size} deleted members loaded`);

    for (const row of pendingWithBalance) {
      const inscriptionId = row.id;
      const balanceToFix  = Number(row.balance);

      try {
        // ── STEP 2: Fetch the inscription from Firebase to get memberId ────────
        // Only 1 read per inscription that has a real balance in SQLite
        const insDoc = await db.collection('pending_members').doc(inscriptionId).get();
        if (!insDoc.exists) {
          skipped.push({ id: inscriptionId, reason: 'inscription not in Firebase' });
          continue;
        }

        const memberId = insDoc.data().memberId;
        if (!memberId) {
          skipped.push({ id: inscriptionId, name: `${row.prenom} ${row.nom}`, reason: 'no memberId linked yet' });
          continue;
        }

        // ── STEP 3: Skip deleted members ──────────────────────────────────────
        if (deletedIds.has(memberId)) {
          skipped.push({ id: inscriptionId, memberId, name: `${row.prenom} ${row.nom}`, reason: 'member was deleted' });
          continue;
        }

        // ── STEP 4: Fetch member from Firebase ────────────────────────────────
        const memberRef  = db.collection('members').doc(memberId);
        const memberSnap = await memberRef.get();
        if (!memberSnap.exists) {
          skipped.push({ id: inscriptionId, memberId, name: `${row.prenom} ${row.nom}`, reason: 'member not in Firebase (deleted?)' });
          continue;
        }

        const memberData     = memberSnap.data();
        const currentBalance = Number(memberData.balance || 0);
        const gymId          = memberData.location || memberData.gymId || row.gym_id || 'dokarat';

        // Skip if already has a correct balance
        if (currentBalance > 0) {
          skipped.push({ memberId, name: memberData.fullName, gymId, reason: `balance already set: ${currentBalance} DH` });
          continue;
        }

        // ── STEP 5: Fix balance in Firebase ───────────────────────────────────
        await memberRef.update({
          balance: balanceToFix,
          inscriptionId: inscriptionId, // ensure link is there
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        // ── STEP 6: Fix balance in SQLite cache ───────────────────────────────
        const updatedSnap = await memberRef.get();
        lc.upsertMembers(gymId, [{ id: memberId, ...updatedSnap.data() }]);

        fixed.push({ memberId, name: memberData.fullName, gymId, balanceFixed: balanceToFix, inscriptionId });
        console.log(`✅ [fix-balances] ${memberData.fullName} (${gymId}) → balance set to ${balanceToFix} DH`);

      } catch (rowErr) {
        errors.push({ inscriptionId, error: rowErr.message });
        console.error(`❌ [fix-balances] Error for inscription ${inscriptionId}:`, rowErr.message);
      }
    }

    // ── STEP 7: Mark as done — endpoint becomes no-op from now on ─────────────
    lc.setMeta('balance_fix_done', new Date().toISOString());

    const summary = { ok: true, fixed: fixed.length, skipped: skipped.length, errors: errors.length, fixedList: fixed };
    console.log(`✅ [fix-member-balances] DONE. Fixed: ${fixed.length} | Skipped: ${skipped.length} | Errors: ${errors.length}`);
    res.json(summary);

  } catch (err) {
    console.error('[fix-member-balances] Fatal Error:', err);
    res.status(500).json({ error: err.message });
  }
});




// ─────────────────────────────────────────────────────────────────────────────
// Mount Routers
// ─────────────────────────────────────────────────────────────────────────────
app.use('/api/members',     require('./routes/members')(deps));
app.use('/api/register',    require('./routes/register')(deps));
app.use('/api/payments',    require('./routes/payments')(deps));
app.use('/api/sales',       require('./routes/sales')(deps));
app.use('/api/relance',     require('./routes/relance')(deps));   // 🎂 Relance: birthdays, expiring subs, inactive
// analytics router — stored so we can call pollDoorEntries() from the interval

const analyticsRouter = require('./routes/analytics')(deps);
app.use('/', analyticsRouter); // mounts /api/live-entries, /api/live-count, /api/analytics/*
app.use('/',                require('./routes/courses')(deps));          // /api/courses, /api/coaches, /public/courses
app.use('/',                require('./routes/inscriptions.public')(deps));    // /public/inscriptions, /public/members/search, /public/debtors, /public/settle-balance
app.use('/',                require('./routes/inscriptions.dashboard')(deps)); // /api/inscriptions (GET/PATCH/confirm/delete/set-pdf)
app.use('/',                require('./routes/inscriptions.admin')(deps));     // /recover-register, /recover-members, /api/inscriptions/fix-pdf-urls
app.use('/',                require('./routes/config')(deps));      // /public/pass, /api/chat, config
app.use('/',                require('./routes/activity')(deps));    // /api/activity/logs
app.use('/',                require('./routes/recruitment')(deps)); // /api/recruitment/applications
app.use('/',                require('./routes/scan')(deps));          // /public/scan-cin, /public/scan-contract, /public/save-contract-scan, /api/contracts
app.use('/',                require('./routes/auralix')(deps));   // /api/auralix/* (Firebase token auth)

// ─────────────────────────────────────────────────────────────────────────────
// PUSH NOTIFICATIONS — POST /api/send-notification
// Fetches member's expoPushToken from Firestore and dispatches via Expo.
// Protected: requires valid Azure token (dashboard session).
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/send-notification', _vat, async (req, res) => {
  const { memberId, title, body, data } = req.body;

  if (!memberId || !title || !body) {
    return res.status(400).json({ ok: false, error: 'memberId, title, and body are required.' });
  }

  try {
    // 1. Fetch member's push token from Firestore
    const memberSnap = await db.collection('members').doc(memberId).get();
    if (!memberSnap.exists) {
      return res.status(404).json({ ok: false, error: `Member ${memberId} not found.` });
    }

    const token = memberSnap.data()?.expoPushToken;
    if (!token || !token.startsWith('ExponentPushToken')) {
      return res.status(422).json({ ok: false, error: 'Member has no valid Expo push token.' });
    }

    // 2. Send via Expo Push API
    const expoRes = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(process.env.EXPO_ACCESS_TOKEN
          ? { 'Authorization': `Bearer ${process.env.EXPO_ACCESS_TOKEN}` }
          : {}),
      },
      body: JSON.stringify({
        to: token,
        sound: 'default',
        title,
        body,
        data: data || {},
      }),
    });

    const expoJson = await expoRes.json();
    const ticket = Array.isArray(expoJson.data) ? expoJson.data[0] : expoJson;

    if (ticket?.status === 'ok' || expoRes.ok) {
      console.log(`✅ [push] Sent to member ${memberId}`);
      return res.json({ ok: true, sent: 1, memberId, ticket });
    } else {
      console.warn(`⚠️ [push] Expo error for ${memberId}:`, ticket);
      return res.status(502).json({ ok: false, error: ticket?.message || 'Expo API error', ticket });
    }

  } catch (err) {
    console.error('🔥 [push] Error:', err.message);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PUSH NOTIFICATIONS — POST /api/send-notification-bulk
// Sends to multiple members by audience filter (all active, expiring, expired).
// Body: { audience: 'all'|'expiring'|'expired', gymId?, title, body, data? }
// Rate-limited: 100 per batch, 200ms pause between batches (≤ 500 notif/sec safe).
// ─────────────────────────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

app.post('/api/send-notification-bulk', _vat, async (req, res) => {
  const { audience = 'all', gymId, title, subtitle, body, data } = req.body;
  if (!title || !body) return res.status(400).json({ ok: false, error: 'title and body required' });

  try {
    const col = db.collection('members');
    const now = new Date().toISOString().slice(0, 10);
    const in7 = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);

    let q = col.where('expoPushToken', '!=', null);
    if (audience === 'expiring') { q = q.where('expiresOn', '>=', now).where('expiresOn', '<=', in7); }
    else if (audience === 'expired') { q = q.where('expiresOn', '<', now); }
    else { q = q.where('status', '==', 'active'); }

    const snap = await q.get();
    let members = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    if (gymId && gymId !== 'all') members = members.filter(m => m.gymId === gymId || m.location === gymId);

    const valid = members.filter(m => m.expoPushToken?.startsWith('ExponentPushToken'));
    if (!valid.length) return res.json({ ok: true, sent: 0, failed: 0, total: 0, skipped: members.length });

    // Batch to Expo: 100 per request, 200ms between batches (firewall against rate limits)
    const BATCH_SIZE = 100;
    const BATCH_DELAY_MS = 200;
    let sent = 0, failed = 0;
    const totalBatches = Math.ceil(valid.length / BATCH_SIZE);

    for (let i = 0; i < valid.length; i += BATCH_SIZE) {
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      const chunk = valid.slice(i, i + BATCH_SIZE);
      const messages = chunk.map(m => ({
        to: m.expoPushToken, sound: 'default', title, subtitle: subtitle || undefined, body, data: data || {},
      }));

      try {
        const r = await fetch('https://exp.host/--/api/v2/push/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify(messages),
        });
        const j = await r.json();
        (j.data || []).forEach(t => { if (t.status === 'ok') sent++; else failed++; });
        console.log(`📤 [push-bulk] batch ${batchNum}/${totalBatches} — sent=${sent} failed=${failed}`);
      } catch {
        failed += chunk.length;
      }

      // Rate-limit firewall: pause between batches (except after last batch)
      if (i + BATCH_SIZE < valid.length) {
        await sleep(BATCH_DELAY_MS);
      }
    }

    console.log(`✅ [push-bulk] DONE audience=${audience} gym=${gymId||'all'} sent=${sent} failed=${failed} total=${valid.length}`);
    return res.json({ ok: true, sent, failed, total: valid.length, batches: totalBatches });
  } catch (err) {
    console.error('🔥 [push-bulk] Error:', err.message);
    return res.status(500).json({ ok: false, error: err.message });
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// Healthcheck
// ─────────────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));


// (inject-stats endpoint moved above route mounts — see line ~193)

// Debug: see what your token contains (temporary — remove after fixing ADMIN_EMAILS)
app.get('/me', _vat, (req, res) => res.json({
  isAdmin: req.isAdmin,
  isManager: req.isManager,
  email: req.user?.preferred_username || req.user?.upn || '⚠️ NO EMAIL CLAIM',
  name: req.user?.name,
  roles: req.user?.roles || [],
  oid: req.user?.oid,
}));

// ─────────────────────────────────────────────────────────────────────────────
// Startup & Seeding
// ─────────────────────────────────────────────────────────────────────────────
async function seedSQLiteHistoricalStats() {
  try {
    if (isQuotaExceeded()) return;
    const cacheStats = lc.getCacheStats();
    console.log(`📡 Current Local Cache Stats: entries=${cacheStats.entries}, members=${cacheStats.members}, payments=${cacheStats.payments}`);
    
    // Seed Door Stats
    console.log('🚀 Checking/Seeding SQLite with 30-day stats...');
      const anchorStr = lc.getMoroccanDateStr ? lc.getMoroccanDateStr() : new Date().toISOString().slice(0,10);
      const [sy, sm, sd] = anchorStr.split('-').map(Number);
      const seedAnchor = new Date(sy, sm - 1, sd);
      for (const gymId of ['dokarat', 'marjane']) {
        const dateStrs = [], docIds = [];
        const missingDates = [];
        for (let i = 29; i >= 0; i--) {
          const dd = new Date(seedAnchor);
          dd.setDate(dd.getDate() - i);
          const d = `${dd.getFullYear()}-${String(dd.getMonth()+1).padStart(2,'0')}-${String(dd.getDate()).padStart(2,'0')}`;
          dateStrs.push(d);
        // 🔒 DISK-FIRST: Only fetch from Firebase if this date has no data on disk
        const existing = lc.getDailyStat ? lc.getDailyStat(gymId, d) : null;
        if (!existing || !existing.count) {
          docIds.push(d);
          missingDates.push(d);
        }
      }
      if (missingDates.length === 0) {
        console.log(`  ⏭️  ${gymId}: all 30 days already on disk — skipping.`);
        continue;
      }
      // 🔒 DISK-ONLY: Compute daily counts from the local entries table — zero Firebase reads
      console.log(`  📊 ${gymId}: computing ${missingDates.length} missing days from local entries...`);
      for (const d of missingDates) {
        const row = lc.db.prepare(
          `SELECT COUNT(*) as cnt, COUNT(DISTINCT name) as unique_cnt FROM entries WHERE gym_id=? AND date=?`
        ).get(gymId, d);
        if (row && row.cnt > 0) {
          lc.upsertDailyStat(gymId, d, row.unique_cnt || row.cnt, row.cnt);
        }
      }
    }
    console.log('  📊 Daily stats seeding checked.');

    // ── Auto-sync: full current-month register for all gyms ──────────────────
    // ✅ SQLite-first: Only fetch from Firestore if SQLite is empty OR data is stale.
    // This prevents burning thousands of reads on every server restart (locally + Render).
    const GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
    const now2 = new Date();
    const toDS = (d) => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    const monthStart = new Date(now2.getFullYear(), now2.getMonth(), 1);

    // ── Cooldown guard: skip if synced within last hour ──────────────────────
    const lastRegSync = lc.getMeta('last_register_sync');
    const msSinceRegSync = lastRegSync ? Date.now() - new Date(lastRegSync).getTime() : Infinity;
    const REGISTER_SYNC_COOLDOWN_MS = 60 * 60 * 1000; // 1 hour

    // Count total SQLite register entries for this month across all gyms
    let totalSQLiteEntries = 0;
    for (const gid of GYMS) {
      const c = new Date(monthStart);
      while (c <= now2) { totalSQLiteEntries += lc.getRegister(gid, toDS(c)).length; c.setDate(c.getDate()+1); }
    }

    if (totalSQLiteEntries >= 20 && msSinceRegSync < REGISTER_SYNC_COOLDOWN_MS) {
      // ✅ SQLite already has substantial data AND we synced recently — skip Firestore
      console.log(`⏭️  Register sync skipped — SQLite has ${totalSQLiteEntries} entries. Using persistent disk. ✅`);
    } else {
      // 🌐 SQLite is empty or stale — pull from Firestore
      console.log(`📋 Register auto-sync: checking current month... (SQLite has ${totalSQLiteEntries} entries)`);
      for (const gid of GYMS) {
        try {
          const cursor = new Date(monthStart);
          let fetched = 0;
          while (cursor <= now2) {
            const dateStr = toDS(cursor);
            
            // ✅ [OPTIMIZATION] Only fetch if SQLite has 0 entries for this specific day
            // This prevents re-downloading thousands of records we already have on disk.
            if (lc.getRegister(gid, dateStr).length > 0 && cursor.getTime() < now2.getTime() - (24*60*60*1000)) {
               cursor.setDate(cursor.getDate() + 1);
               continue; 
            }

            const docRef = db.collection('megafit_daily_register').doc(`${gid}_${dateStr}`);
            const snap = await docRef.collection('entries').get();
            if (!snap.empty) {
              lc.upsertRegister(gid, dateStr, snap.docs.map(d => ({ id: d.id, ...d.data(), date: dateStr, gymId: gid })));
              fetched += snap.size;
            }

            const decSnap = await docRef.collection('decaissements').get();
            if (!decSnap.empty) {
              lc.upsertDecaissements(gid, dateStr, decSnap.docs.map(d => ({ id: d.id, ...d.data() })));
            }

            cursor.setDate(cursor.getDate() + 1);
          }
          console.log(`  ✅ [${gid}] monthly sync: ${fetched} new/updated entries saved to disk.`);
        } catch (gErr) {
          if (gErr.code === 8) { setQuotaExceeded(); break; }
          console.warn(`  ⚠️ [${gid}] register sync failed:`, gErr.message);
        }
      }
      lc.setMeta('last_register_sync', new Date().toISOString());
      console.log('✨ SQLite register sync complete.');
    }
  } catch (err) {
    if (err.code === 8) setQuotaExceeded();
    console.warn('⚠️ SQLite seed skipped or partial:', err.message);
  }
}

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ API running on port ${PORT}`);
  scheduleNightlySync(db, apiCache, isQuotaExceeded);

  // ── Server-side door entries poll (60s) ───────────────────────────────────────
  async function runDoorPoll() {
    if (isQuotaExceeded()) return;
    try { await analyticsRouter.pollDoorEntries(); }
    catch (e) { console.warn('[DOOR POLL] error:', e.message); }
  }
  setTimeout(runDoorPoll, 5000);
  setInterval(runDoorPoll, 60 * 1000);

  // ── Gap fill: recover missing historical days on startup ──────────────────
  setTimeout(async () => {
    if (isQuotaExceeded()) return;
    // Only run gap fill if we haven't done it today (persisted in SQLite)
    const lastGapFill = lc.getMeta('last_gap_fill');
    const todayStr = new Date().toISOString().split('T')[0];
    if (lastGapFill === todayStr) {
      console.log('⏭️  Gap fill skipped — already performed today. Disk is warm. 💾');
      return;
    }
    try { 
      await analyticsRouter.gapFillDoorEntries(); 
      lc.setMeta('last_gap_fill', todayStr);
    }
    catch (e) { console.warn('[GAP FILL] startup error:', e.message); }
  }, 15000);


  // ── Archive members seed: once on startup — reads from JSON seed file (zero Firebase reads) ──
  // This populates SQLite from the bundled seed file on first boot. Never calls Firebase.
  setTimeout(syncArchiveMembersOnce, 15000);           // archive: 15s after startup (one-time)
  async function syncArchiveMembersOnce() {
    const alreadySynced = lc.getMeta('archive_members_synced');
    if (alreadySynced) {
      console.log(`⏭️  Archive members already synced to SQLite. Skipping.`);
      return;
    }
    try {
      // ── Try JSON seed file first (zero Firebase reads) ──────────────────
      const seedPath = path.join(__dirname, 'seed_members_all.json');
      if (fs.existsSync(seedPath)) {
        console.log(`📦 Loading ALL members from seed file → SQLite (zero Firebase reads)...`);
        const members = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
        
        // Group by gym to use lc.upsertMembers correctly
        const byGym = {};
        members.forEach(m => {
          const g = m.location || m.gymId || 'dokarat';
          let key = 'dokarat';
          if (g.toLowerCase().includes('marjane') || g.toLowerCase().includes('saiss')) key = 'marjane';
          if (g.toLowerCase().includes('casa1')) key = 'casa1';
          if (g.toLowerCase().includes('casa2')) key = 'casa2';
          
          if (!byGym[key]) byGym[key] = [];
          byGym[key].push(m);
        });

        for (const [gymId, gymMembers] of Object.entries(byGym)) {
          lc.upsertMembers(gymId, gymMembers);
          lc.setMeta(`member_sync_${gymId}`, String(Date.now()));
        }

        lc.setMeta('archive_members_synced', new Date().toISOString());
        console.log(`📦 Archive seed complete: ${members.length} members in SQLite. Zero Firebase reads! ✅`);
        return;
      }

      // ── Fallback: fetch from Firestore if seed file missing ─────────────
      if (isQuotaExceeded()) return;
      console.log(`📦 Seed file not found — syncing archive members from Firestore (one-time)...`);
      for (const gymId of GYMS_ALL) {
        const all = await fetchAllMembers(gymId);
        if (all.length > 0) {
          lc.upsertMembers(gymId, all);
          console.log(`  ✅ ${gymId}: ${all.length} members saved to SQLite`);
        }
        lc.setMeta(`member_sync_${gymId}`, String(Date.now()));
      }
      lc.setMeta('archive_members_synced', new Date().toISOString());
      console.log(`📦 Archive sync complete. ✅`);
    } catch (e) {
      console.warn('[ARCHIVE SYNC] error:', e.message);
    }
  }

  // ── Pending Cache Self-Heal: backfill phone/birthday/photo if missing ─────
  // Runs once on Render after deploying the new schema. Detected by checking
  // if telephone column is empty when we have pdf records with no phone.
  setTimeout(async () => {
    try {
      const metaKey = 'pending_cache_backfill_v2';
      if (lc.getMeta(metaKey)) return; // already done
      
      const missing = lc.db.prepare(
        `SELECT COUNT(*) as cnt FROM pending_cache WHERE telephone IS NULL AND pdf_url IS NOT NULL`
      ).get();
      
      if (!missing || missing.cnt === 0) {
        lc.setMeta(metaKey, new Date().toISOString());
        console.log('⏭️  Pending cache backfill skipped — all records already have phone data. ✅');
        return;
      }
      
      console.log(`🔄 [BACKFILL] ${missing.cnt} pending records missing phone/birthday — syncing from Firebase...`);
      const snap = await db.collection('pending_members').get();
      let count = 0;
      snap.forEach(doc => {
        const data = doc.data();
        lc.setPending({ id: doc.id, ...data });
        count++;
      });
      lc.setMeta(metaKey, new Date().toISOString());
      console.log(`✅ [BACKFILL] Pending cache fully refreshed: ${count} records updated with phone/birthday/photo!`);
    } catch (e) {
      console.warn('[BACKFILL] pending_cache self-heal error:', e.message);
    }
  }, 20000); // 20s after startup



  setTimeout(async () => {
    if (isQuotaExceeded()) return;
    await seedSQLiteHistoricalStats();

    // 🛠️ DATABASE SELF-HEALING: Normalize timestamps on startup (ensures correct sorting)
    try {
      const tFix = lc.db.prepare("UPDATE entries SET timestamp = REPLACE(timestamp, 'T', ' ') WHERE timestamp LIKE '%T%'").run();
      const zFix = lc.db.prepare("UPDATE entries SET timestamp = REPLACE(timestamp, 'Z', '') WHERE timestamp LIKE '%Z%'").run();
      if (tFix.changes > 0 || zFix.changes > 0) {
        console.log(`🧹 [CLEANUP] Normalized ${tFix.changes + zFix.changes} timestamps in database.`);
      }
    } catch (err) {
      console.error("❌ Failed to normalize database timestamps:", err);
    }

    // --- ONE-TIME RENDER DISK UPDATE FROM LOG FILES ---
    if (!lc.getMeta('dokarat_hard_reset_2026_04_27')) {
      console.log("🛠️  PERFORMING ONE-TIME HARD RESET FOR DOKKARATE FROM LOG FILES...");
      try {
        lc.db.transaction(() => {
          lc.db.prepare("DELETE FROM entries WHERE gym_id = 'dokarat' AND date <= '2026-04-27'").run();
          const fs = require('fs');
          const path = require('path');
          
          const entriesPath = path.join(__dirname, 'seed_entries.json');
          if (fs.existsSync(entriesPath)) {
            const insertStmt = lc.db.prepare("INSERT INTO entries (id, gym_id, date, timestamp, name, method, status, is_face) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            const entriesData = JSON.parse(fs.readFileSync(entriesPath, 'utf8'));
            entriesData.forEach(e => {
              const ts = (e.timestamp || '').replace('T', ' ').replace('Z', '');
              insertStmt.run(e.id, e.gym_id, e.date, ts, e.name, e.method, e.status, e.is_face);
            });
            console.log(`📦 Injected ${entriesData.length} raw entries into disk.`);
          }
          
          const statsPath = path.join(__dirname, 'seed_daily_stats.json');
          if (fs.existsSync(statsPath)) {
            const statsData = JSON.parse(fs.readFileSync(statsPath, 'utf8'));
            statsData.forEach(row => lc.upsertDailyStat(row.gym_id, row.date, row.count, row.raw_count || 0));
            console.log(`📦 Injected ${statsData.length} daily_stats rows into disk.`);
          }
        })();
        lc.setMeta('dokarat_hard_reset_2026_04_27', 'done');
        console.log("✅ ONE-TIME HARD RESET COMPLETE!");
      } catch (err) {
        console.error("❌ Failed one-time hard reset:", err);
      }
    }
    // --------------------------------------------------

    // --- ONE-TIME MARJANE REGISTER SEED (Apr 25-27 2026) ---
    if (!lc.getMeta('marjane_register_seed_2026_04_27')) {
      try {
        const regPath = path.join(__dirname, 'seed_register_marjane_apr2026.json');
        if (fs.existsSync(regPath)) {
          const regData = JSON.parse(fs.readFileSync(regPath, 'utf8'));
          const stmt = lc.db.prepare(`
            INSERT OR IGNORE INTO register_cache
              (id, gym_id, date, nom, contrat, commercial, cin, tel, tpe, espece, virement, cheque, prix, reste, abonnement, note_reste, created_at, synced_at)
            VALUES
              (@id, @gym_id, @date, @nom, @contrat, @commercial, @cin, @tel, @tpe, @espece, @virement, @cheque, @prix, @reste, @abonnement, @note_reste, @created_at, @synced_at)
          `);
          const now = new Date().toISOString();
          lc.db.transaction((rows) => { rows.forEach(r => stmt.run({ ...r, synced_at: now })); })(regData);
          console.log(`📦 Injected ${regData.length} Marjane register entries (Apr 25-27).`);
        }
        lc.setMeta('marjane_register_seed_2026_04_27', 'done');
      } catch (err) {
        console.error('❌ Failed marjane register seed:', err);
      }
    }
    // --------------------------------------------------

    // Smart guard: run repair only if SQLite is missing data (< 20 days with real data)
    const existingStats = lc.getDailyStats('dokarat', 30).filter(s => s.count > 0);
    const hasFullData = existingStats.length >= 20;

    const REPAIR_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 Hours — disk persists this, safe to skip daily
    const lastRepair = lc.getMeta('last_startup_repair');
    const msSinceLastRepair = lastRepair ? Date.now() - new Date(lastRepair).getTime() : Infinity;

    if (hasFullData && msSinceLastRepair < REPAIR_COOLDOWN_MS) {
      console.log(`⏭️  Startup repair skipped — SQLite already has ${existingStats.length} days of data. Quota saved! ✅`);
    } else if (!hasFullData) {
      // ── Seed from bundled JSON file (ZERO Firebase reads) ──────────────────
      const seedPath = path.join(__dirname, 'seed_daily_stats.json');
      if (fs.existsSync(seedPath)) {
        const seedData = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
        seedData.forEach(row => lc.upsertDailyStat(row.gym_id, row.date, row.count, row.raw_count || 0));
        console.log(`📦 Seeded ${seedData.length} daily_stats rows from local JSON file. Zero Firebase reads! ✅`);
      } else {
        // Fallback: only if seed file is missing, use Firebase (7 days, no forced manual)
        console.log('🛠️  Seed file not found — running 7-day repair from Firebase...');
        await syncGymCounts(db, apiCache, 7, isQuotaExceeded, false);
      }
      lc.setMeta('last_startup_repair', new Date().toISOString());
      console.log('✅ Startup seeding complete.');
    } else {
      // Has data and disk is warm — door poll handles live counts every 60s, no Firebase needed
      console.log(`⏭️  Startup refresh skipped — disk has ${existingStats.length} days, door poll is live. 💾`);
      lc.setMeta('last_startup_repair', new Date().toISOString());
    }
  }, 3000);

  // ── ONE-TIME: Load Odoo members into SQLite for smart AI identification ────
  setTimeout(() => {
    try {
      const count = lc.db.prepare('SELECT COUNT(*) as c FROM odoo_members_cache').get().c;
      if (count > 0) {
        console.log(`⚡ [SMART-ID] Odoo members already loaded: ${count} rows in SQLite.`);
        return;
      }
      const slimPath = path.join(__dirname, 'data', 'odoo_members_slim.json');
      if (!fs.existsSync(slimPath)) {
        console.warn('⚠️  [SMART-ID] odoo_members_slim.json not found — smart identification will be limited.');
        return;
      }
      const members = JSON.parse(fs.readFileSync(slimPath, 'utf8'));
      const normName = s => (s || '').replace(/\s+/g, ' ').trim().toUpperCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const insert = lc.db.prepare(`
        INSERT OR IGNORE INTO odoo_members_cache (full_name, first_name, last_name, gym_id, status, expires_on, name_norm)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const tx = lc.db.transaction((rows) => { for (const m of rows) insert.run(m.fullName, m.firstName, m.lastName, m.gymId, m.status, m.expiresOn, normName(m.fullName)); });
      tx(members);
      console.log(`✅ [SMART-ID] Loaded ${members.length} Odoo members into SQLite for smart identification.`);
    } catch (err) {
      console.error('❌ [SMART-ID] Failed to load Odoo members:', err.message);
    }
  }, 5000);

  setInterval(async () => {
    if (lc.getDailyStats('dokarat', 30).length < 7 || lc.getDailyStats('marjane', 30).length < 7) {
      await seedSQLiteHistoricalStats();
    }
  }, 60 * 60 * 1000);
});
// ?? TEMPORARY: Clear Auralix cache once to fix the '0 members' issue
lc.db.prepare('DELETE FROM resub_intelligence_cache').run();
console.log('?? [STARTUP] Auralix Intelligence Cache Cleared');
