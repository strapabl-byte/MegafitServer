'use strict';
/**
 * cleanup_anfa.js
 * Wipes all data associated with 'casa1' (Anfa) to start from scratch.
 * Deletes from Firestore and SQLite.
 */
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

const serviceAccount = require('../serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const GYM_ID = 'casa1';

async function cleanupFirestore() {
  console.log(`🧹 Cleaning up Firestore for ${GYM_ID}...`);

  // 1. Delete members
  const memberSnap = await db.collection('members').where('location', '==', GYM_ID).get();
  console.log(`- Found ${memberSnap.size} members.`);
  for (const doc of memberSnap.docs) {
    await doc.ref.delete();
  }

  // 2. Delete courses
  const courseSnap = await db.collection('courses').where('gymId', '==', GYM_ID).get();
  console.log(`- Found ${courseSnap.size} courses.`);
  for (const doc of courseSnap.docs) {
    await doc.ref.delete();
  }

  // 3. Delete daily register entries
  // We need to find all docs in megafit_daily_register that have gymId == 'casa1'
  const regSnap = await db.collection('megafit_daily_register').where('gymId', '==', GYM_ID).get();
  console.log(`- Found ${regSnap.size} register days.`);
  for (const doc of regSnap.docs) {
    // Delete sub-collections first? Firestore doesn't delete sub-collections automatically
    const entries = await doc.ref.collection('entries').get();
    for (const e of entries.docs) await e.ref.delete();
    const decs = await doc.ref.collection('decaissements').get();
    for (const d of decs.docs) await d.ref.delete();
    await doc.ref.delete();
  }

  console.log('✅ Firestore cleanup complete.');
}

function cleanupSQLite() {
  const DB_PATH = path.join(__dirname, '../megafit_cache.db');
  if (!fs.existsSync(DB_PATH)) {
    console.log('⚠️ SQLite database not found at', DB_PATH);
    return;
  }

  console.log(`🧹 Cleaning up SQLite for ${GYM_ID}...`);
  const tables = ['members_cache', 'daily_stats', 'register_cache', 'payments_cache', 'pending_cache', 'incidents_cache'];
  
  for (const table of tables) {
    try {
      execSync(`sqlite3 "${DB_PATH}" "DELETE FROM ${table} WHERE gym_id = '${GYM_ID}';"`);
      console.log(`- Cleaned table ${table} (gym_id).`);
    } catch (e) {
      try {
        execSync(`sqlite3 "${DB_PATH}" "DELETE FROM ${table} WHERE gymId = '${GYM_ID}';"`);
        console.log(`- Cleaned table ${table} (gymId).`);
      } catch (e2) {
        console.warn(`- Could not clean table ${table}: ${e2.message}`);
      }
    }
  }
  console.log('✅ SQLite cleanup complete.');
}

async function run() {
  try {
    await cleanupFirestore();
    cleanupSQLite();
    console.log('✨ All clean! Casa Anfa is now a fresh slate.');
  } catch (err) {
    console.error('❌ Cleanup failed:', err);
  } finally {
    process.exit(0);
  }
}

run();
