'use strict';
// Force-sync: pulls casa2 register entries from Firestore into Render's SQLite cache
// Covers all 9 seeded days (01–09 May 2026)
// Usage: node scratch/force_sync_casa2.js

require('dotenv').config();
const admin = require('firebase-admin');
const { syncGymCounts } = require('../auto_sync');

if (!admin.apps.length) {
  const serviceAccount = require('../serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();
const apiCache = {};

async function run() {
  console.log('\n🔄 Force-syncing Casa Lady Anfa (casa2) — 9 days of May 2026...\n');
  // Sync last 12 days to cover 01–09 May (today is ~10 May)
  await syncGymCounts(db, apiCache, 12, () => false, false, { syncRegisterOnly: true });
  console.log('\n✅ Sync complete! Render SQLite cache is now up to date.\n');
  process.exit(0);
}

run().catch(err => {
  console.error('❌ Sync failed:', err);
  process.exit(1);
});
