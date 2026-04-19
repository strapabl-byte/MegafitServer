'use strict';
// server.js — Entry point. ~100 lines. Mounts routers. Nothing more.
require('dotenv').config();
const express = require('express');
const helmet  = require('helmet');
const cors    = require('cors');
const multer  = require('multer');
const crypto  = require('crypto');
const admin   = require('firebase-admin');
const lc      = require('./localCache');
const { syncGymCounts, scheduleNightlySync } = require('./auto_sync');

// ─────────────────────────────────────────────────────────────────────────────
// App Setup
// ─────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// ─────────────────────────────────────────────────────────────────────────────
// Firebase Admin Init
// ─────────────────────────────────────────────────────────────────────────────
const fs   = require('fs');
const path = require('path');
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
// Mount Routers
// ─────────────────────────────────────────────────────────────────────────────
app.use('/api/members',     require('./routes/members')(deps));
app.use('/api/register',    require('./routes/register')(deps));
app.use('/api/payments',    require('./routes/payments')(deps));
app.use('/api/commercials', require('./routes/commercials')(deps));
app.use('/',                require('./routes/analytics')(deps));   // /api/live-entries, /api/live-count, /api/analytics/*, /api/admin/sync-stats
app.use('/',                require('./routes/courses')(deps));     // /api/courses, /api/coaches, /public/courses, etc.
app.use('/',                require('./routes/inscriptions')(deps));// /public/* & /api/inscriptions
app.use('/',                require('./routes/config')(deps));      // /public/pass, /api/chat, config

// ─────────────────────────────────────────────────────────────────────────────
// Healthcheck
// ─────────────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

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
    if (cacheStats.stats >= 30) { console.log('✅ Daily stats already seeded. Skip bulk fetch.'); return; }
    console.log('🚀 Seeding SQLite with 30-day stats...');

    for (const gymId of ['dokarat', 'marjane']) {
      const dateStrs = [], docIds = [];
      for (let i = 29; i >= 0; i--) {
        const d = new Date(Date.now() + 3600000 - i * 86400000).toISOString().slice(0, 10);
        dateStrs.push(d); docIds.push(`${gymId}_${d}`);
      }
      const snaps = await db.getAll(...docIds.map(id => db.collection('gym_daily_stats').doc(id)));
      snaps.forEach((snap, i) => { const d = snap.exists ? snap.data() : {}; lc.upsertDailyStat(gymId, dateStrs[i], d.count || 0, d.rawCount || 0); });
    }
    console.log('  📊 Daily stats cached.');

    // Seed recent members
    const mSnap = await db.collection('members').orderBy('createdAt', 'desc').limit(50).get();
    if (!mSnap.empty) lc.upsertMembers('all', mSnap.docs.map(d => ({ id: d.id, ...d.data() })));

    // Seed recent register entries
    const rSnap = await db.collectionGroup('entries').orderBy('createdAt', 'desc').limit(50).get();
    if (!rSnap.empty) {
      const grouped = {};
      rSnap.docs.forEach(d => {
        const data = d.data();
        const date = data.createdAt?.toDate ? data.createdAt.toDate().toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);
        const key  = `${data.gymId || 'dokarat'}_${date}`;
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push({ id: d.id, ...data, date });
      });
      for (const [key, entries] of Object.entries(grouped)) {
        const [gid, d] = key.split('_');
        lc.upsertRegister(gid, d, entries);
      }
    }
    console.log('✨ SQLite seeding complete.');
  } catch (err) {
    if (err.code === 8) setQuotaExceeded();
    console.warn('⚠️ SQLite seed skipped or partial:', err.message);
  }
}

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ API running on port ${PORT}`);
  scheduleNightlySync(db, apiCache, isQuotaExceeded);

  setTimeout(async () => {
    if (isQuotaExceeded()) return;
    await seedSQLiteHistoricalStats();

    const REPAIR_COOLDOWN_MS = 60 * 60 * 1000;
    const lastRepair = lc.getMeta('last_startup_repair');
    const msSinceLastRepair = lastRepair ? Date.now() - new Date(lastRepair).getTime() : Infinity;

    if (msSinceLastRepair < REPAIR_COOLDOWN_MS) {
      console.log(`⏭️  Startup repair skipped — last run ${Math.round(msSinceLastRepair / 60000)} min ago. Quota saved! ✅`);
    } else {
      console.log('🛠️  Running startup repair for the last 7 days...');
      await syncGymCounts(db, apiCache, 7, isQuotaExceeded);
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