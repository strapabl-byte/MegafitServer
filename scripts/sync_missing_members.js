'use strict';
// sync_missing_members.js
// Pulls specific members from Firestore and injects them into the SQLite members_cache.
require('dotenv').config();
const admin = require('firebase-admin');
const path  = require('path');
const lc    = require('./localCache');

const localPath = path.join(__dirname, 'serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require(localPath)) });
}
const db = admin.firestore();

// ── Member IDs to sync (from diagnosis) ───────────────────────────────────
const MEMBER_IDS = [
  'OCmzdlyLAsxwC0Iosqnt', // Mohammed Benjelloun
  '90hhdDk8tQzsCr8Kl6WW', // DIOURI OUMAIMA
];

async function run() {
  console.log(`\n🔄 Syncing ${MEMBER_IDS.length} members from Firestore → SQLite...\n`);
  
  const toSync = [];
  for (const id of MEMBER_IDS) {
    const snap = await db.collection('members').doc(id).get();
    if (!snap.exists) { console.log(`❌ ${id} not found in Firestore`); continue; }
    const m = snap.data();
    console.log(`✅ Found: ${m.fullName} (${m.location})`);
    toSync.push({ id: snap.id, ...m });
  }

  if (toSync.length === 0) { console.log('Nothing to sync.'); process.exit(0); }

  // Group by gymId and upsert
  const byGym = {};
  toSync.forEach(m => {
    const g = m.location || m.gymId || 'dokarat';
    if (!byGym[g]) byGym[g] = [];
    byGym[g].push(m);
  });

  for (const [gymId, members] of Object.entries(byGym)) {
    lc.upsertMembers(gymId, members);
    console.log(`\n💾 Injected ${members.length} member(s) into SQLite for gym: ${gymId}`);
    members.forEach(m => console.log(`   • ${m.fullName}`));
  }

  // Verify
  console.log('\n=== Verification ===\n');
  MEMBER_IDS.forEach(id => {
    const row = lc.db.prepare('SELECT full_name, gym_id, status, expires_on FROM members_cache WHERE id = ?').get(id);
    if (row) {
      console.log(`✅ ${row.full_name} | gym: ${row.gym_id} | expires: ${row.expires_on}`);
    } else {
      console.log(`❌ ${id} still NOT in SQLite`);
    }
  });

  console.log('\nDone. Members should now be visible in the Members page.\n');
  process.exit(0);
}

run().catch(err => { console.error('Fatal:', err); process.exit(1); });
