'use strict';
// server.js — Entry point. ~100 lines. Mounts routers. Nothing more.
require('dotenv').config();
const express = require('express');
const helmet  = require('helmet');
const cors    = require('cors');
const multer  = require('multer');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');
const admin   = require('firebase-admin');
const lc      = require('./localCache');
const { syncGymCounts, scheduleNightlySync } = require('./auto_sync');

// ─────────────────────────────────────────────────────────────────────────────
// App Setup
// ─────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
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
  const secret = req.headers['x-inject-secret'];
  const expected = process.env.INJECT_SECRET || 'megafit-seed-2026';
  if (secret !== expected) return res.status(403).json({ error: 'Forbidden' });
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
// System Stats — live SQLite disk usage for Megaeye dashboard
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/system-stats', (req, res) => {
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
  const secret = req.headers['x-inject-secret'];
  const expected = process.env.INJECT_SECRET || 'megafit-seed-2026';
  if (secret !== expected) return res.status(403).json({ error: 'Forbidden' });
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
  const secret   = req.headers['x-inject-secret'];
  const expected = process.env.INJECT_SECRET || 'megafit-seed-2026';
  if (secret !== expected) return res.status(403).json({ error: 'Forbidden' });

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
  const secret   = req.headers['x-inject-secret'];
  const expected = process.env.INJECT_SECRET || 'megafit-seed-2026';
  if (secret !== expected) return res.status(403).json({ error: 'Forbidden' });

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
// Mount Routers
// ─────────────────────────────────────────────────────────────────────────────
app.use('/api/members',     require('./routes/members')(deps));
app.use('/api/register',    require('./routes/register')(deps));
app.use('/api/payments',    require('./routes/payments')(deps));
app.use('/api/commercials', require('./routes/commercials')(deps));
// analytics router — stored so we can call pollDoorEntries() from the interval
const analyticsRouter = require('./routes/analytics')(deps);
app.use('/', analyticsRouter); // mounts /api/live-entries, /api/live-count, /api/analytics/*
app.use('/',                require('./routes/courses')(deps));     // /api/courses, /api/coaches, /public/courses, etc.
app.use('/',                require('./routes/inscriptions')(deps));// /public/* & /api/inscriptions
app.use('/',                require('./routes/config')(deps));      // /public/pass, /api/chat, config
app.use('/',                require('./routes/activity')(deps));    // /api/activity/logs

// ─────────────────────────────────────────────────────────────────────────────
// Healthcheck
// ─────────────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// (inject-stats endpoint moved above route mounts — see line ~193)

// Debug: see what your token contains (temporary — remove after fixing ADMIN_EMAILS)
const { verifyAzureToken: _vat } = require('./middleware/auth');
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
    for (const gymId of ['dokarat', 'marjane']) {
      const dateStrs = [], docIds = [];
      for (let i = 29; i >= 0; i--) {
        const d = new Date(Date.now() + 3600000 - i * 86400000).toISOString().slice(0, 10);
        dateStrs.push(d); docIds.push(`${gymId}_${d}`);
      }
      const snaps = await db.getAll(...docIds.map(id => db.collection('gym_daily_stats').doc(id)));
      snaps.forEach((snap, i) => { 
        if (snap.exists) {
          const d = snap.data();
          lc.upsertDailyStat(gymId, dateStrs[i], d.count || 0, d.rawCount || 0); 
        }
        // If snap doesn't exist, LEAVE the SQLite data alone (don't overwrite with 0)
      });
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

    if (totalSQLiteEntries >= 5 && msSinceRegSync < REGISTER_SYNC_COOLDOWN_MS) {
      // ✅ SQLite already has data AND we synced recently — skip Firestore entirely
      console.log(`⏭️  Register sync skipped — SQLite has ${totalSQLiteEntries} entries, last sync ${Math.round(msSinceRegSync/60000)} min ago. Quota saved! ✅`);
    } else {
      // 🌐 SQLite is empty or stale — pull from Firestore
      console.log(`📋 Register auto-sync: pulling current month for all gyms... (SQLite had ${totalSQLiteEntries} entries)`);
      for (const gid of GYMS) {
        try {
          const cursor = new Date(monthStart);
          let fetched = 0;
          while (cursor <= now2) {
            const dateStr = toDS(cursor);
            const docRef = db.collection('megafit_daily_register').doc(`${gid}_${dateStr}`);

            // Fetch entries
            const snap = await docRef.collection('entries').get();
            if (!snap.empty) {
              lc.upsertRegister(gid, dateStr, snap.docs.map(d => ({ id: d.id, ...d.data(), date: dateStr, gymId: gid })));
              fetched += snap.size;
            }

            // ✅ Also fetch décaissements so KPI can subtract them correctly
            const decSnap = await docRef.collection('decaissements').get();
            if (!decSnap.empty) {
              lc.upsertDecaissements(gid, dateStr, decSnap.docs.map(d => ({ id: d.id, ...d.data() })));
            }

            cursor.setDate(cursor.getDate() + 1);
          }
          // Compute monthly revenue from updated cache (entries - decaissements)
          let rev = 0;
          const c2 = new Date(monthStart);
          while (c2 <= now2) {
            const ds2 = toDS(c2);
            lc.getRegister(gid, ds2).forEach(e => { rev += (Number(e.tpe)||0)+(Number(e.espece)||0)+(Number(e.virement)||0)+(Number(e.cheque)||0); });
            (lc.getDecaissements(gid, ds2)||[]).forEach(d => { rev -= Number(d.montant)||0; });
            c2.setDate(c2.getDate()+1);
          }
          console.log(`  ✅ [${gid}] fetched ${fetched} entries | month (net): ${rev.toLocaleString()} DH`);
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
  // Replaces per-request Firestore calls. One poll = all clients served from SQLite.
  async function runDoorPoll() {
    if (isQuotaExceeded()) return;
    try { await analyticsRouter.pollDoorEntries(); }
    catch (e) { console.warn('[DOOR POLL] error:', e.message); }
  }
  setTimeout(runDoorPoll, 5000);        // first poll 5s after startup (warm SQLite)
  setInterval(runDoorPoll, 60 * 1000); // then every 60 seconds

  setTimeout(async () => {
    if (isQuotaExceeded()) return;
    await seedSQLiteHistoricalStats();

    // Smart guard: run repair only if SQLite is missing data (< 20 days with real data)
    const existingStats = lc.getDailyStats('dokarat', 30).filter(s => s.count > 0);
    const hasFullData = existingStats.length >= 20;

    const REPAIR_COOLDOWN_MS = 60 * 60 * 1000; // 1 hour
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
      // Has data but cooldown expired → light 7-day refresh (1-read per day)
      console.log('🛠️  Running light 7-day refresh...');
      await syncGymCounts(db, apiCache, 7, isQuotaExceeded, false);
      lc.setMeta('last_startup_repair', new Date().toISOString());
      console.log('✅ Startup repair complete.');
    }
  }, 3000);

  setInterval(async () => {
    if (lc.getDailyStats('dokarat', 30).length < 7 || lc.getDailyStats('marjane', 30).length < 7) {
      await seedSQLiteHistoricalStats();
    }
  }, 60 * 60 * 1000);
});