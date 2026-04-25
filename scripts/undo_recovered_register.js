'use strict';
// undo_recovered_register.js
// Uses SQLite to find the auto-recovered entries, then deletes them from both
// SQLite and Firestore directly (no collectionGroup index required).
require('dotenv').config();

const admin = require('firebase-admin');
const path  = require('path');
const fs    = require('fs');
const lc    = require('./localCache');

// ── Firebase Init ──────────────────────────────────────────────────────────
const localPath = path.join(__dirname, 'serviceAccount.json');
if (!fs.existsSync(localPath)) { console.error('❌ serviceAccount.json not found'); process.exit(1); }
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require(localPath)) });
}
const db = admin.firestore();

async function run() {
  console.log('\n🔍 Finding auto-recovered entries in SQLite...\n');

  // SQLite is local — find all entries written by the recovery script
  const rows = lc.db.prepare(`
    SELECT id, gym_id, date, nom, prix
    FROM register_cache
    WHERE note_reste LIKE '%RÉCUPÉRÉ%'
       OR note_reste LIKE '%RECUPERE%'
    ORDER BY date DESC
  `).all();

  console.log(`Found ${rows.length} auto-recovered entries in SQLite.\n`);

  if (rows.length === 0) {
    console.log('Nothing to delete. Done.');
    process.exit(0);
  }

  let deleted = 0;
  const errors = [];

  for (const row of rows) {
    const { id, gym_id, date, nom, prix } = row;
    const docPath = `megafit_daily_register/${gym_id}_${date}/entries/${id}`;
    process.stdout.write(`  🗑  ${nom} | ${prix} DH | ${gym_id}_${date}... `);

    try {
      // 1. Delete from Firestore
      await db.doc(docPath).delete();
      // 2. Delete from SQLite
      lc.deleteRegisterEntry(gym_id, date, id);
      console.log('✅');
      deleted++;
    } catch (e) {
      console.log(`❌ ${e.message}`);
      errors.push({ id, nom, error: e.message });
    }
  }

  console.log(`\n─────────────────────────────────────────────`);
  console.log(`✅ Deleted ${deleted} entries.`);
  if (errors.length) {
    console.log(`❌ ${errors.length} errors:`);
    errors.forEach(e => console.log(`   • ${e.nom}: ${e.error}`));
  }
  console.log('\nThe pending_members remain in "awaiting_payment" — go to the Payments page to accept them one by one.\n');
  process.exit(0);
}

run().catch(err => { console.error('Fatal:', err); process.exit(1); });
