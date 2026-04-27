'use strict';
/**
 * sync_members_full.js
 * ────────────────────
 * Performs a complete sync of the 'members' collection from Firestore 
 * into the local SQLite 'members_cache' table.
 * 
 * This fixes the "Ce membre a été supprimé" issue by ensuring that the 
 * local cache only contains IDs that actually exist in Firestore.
 */
require('dotenv').config();
const admin = require('firebase-admin');
const path  = require('path');
const lc    = require('../localCache');

const serviceAccountPath = path.join(__dirname, '..', 'serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(require(serviceAccountPath))
  });
}
const db = admin.firestore();

async function main() {
  console.log('🚀 Starting FULL Member Sync: Firestore → SQLite...');

  // 1. Fetch ALL members from Firestore
  // Note: We use a simple query. For very large collections (10k+), 
  // pagination might be needed, but for MegaFit ~6k should be fine in one go.
  const snapshot = await db.collection('members').get();
  
  if (snapshot.empty) {
    console.log('⚠️ No members found in Firestore. Aborting to prevent accidental wipe.');
    process.exit(0);
  }

  console.log(`✅ Fetched ${snapshot.size} members from Firestore.`);

  // 2. Group by location/gymId
  const byGym = {};
  snapshot.docs.forEach(doc => {
    const m = doc.data();
    const gymId = m.location || m.gymId || 'dokarat';
    
    // Normalize gymId to match our system keys
    let key = 'dokarat';
    if (gymId.toLowerCase().includes('marjane') || gymId.toLowerCase().includes('saiss')) key = 'marjane';
    if (gymId.toLowerCase().includes('casa1')) key = 'casa1';
    if (gymId.toLowerCase().includes('casa2')) key = 'casa2';

    if (!byGym[key]) byGym[key] = [];
    byGym[key].push({ id: doc.id, ...m });
  });

  // 3. Clear and Upsert into SQLite
  console.log('\n💾 Updating SQLite cache...');
  
  // We'll wipe the WHOLE table first to get rid of stale IDs
  lc.db.prepare('DELETE FROM members_cache').run();
  console.log('🗑️  Local members_cache wiped.');

  for (const [gymId, members] of Object.entries(byGym)) {
    console.log(`   ⏳ Processing ${gymId} (${members.length} members)...`);
    // upsertMembers handles the insertion logic
    lc.upsertMembers(gymId, members);
  }

  console.log('\n✨ Sync Complete!');
  const stats = lc.getCacheStats();
  console.log(`📊 Local SQLite now has ${stats.members} members.`);
  
  process.exit(0);
}

main().catch(err => {
  console.error('❌ Sync Failed:', err);
  process.exit(1);
});
