/**
 * backfill_register_cin.js
 * One-time script: For each register entry with an empty CIN,
 * look up the corresponding pending_member by contractNumber
 * and fill in the CIN from the pending_member record.
 */

const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');
const Database = require('better-sqlite3');

if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();
const cacheDb = new Database('megafit_cache.db');

async function run() {
  // 1. Get all SQLite register entries with empty CIN
  const rows = cacheDb.prepare("SELECT * FROM register_cache WHERE (cin IS NULL OR cin = '') AND contrat != '' AND contrat IS NOT NULL ORDER BY date DESC").all();
  console.log(`Found ${rows.length} register entries with empty CIN`);

  let fixed = 0, skipped = 0, notFound = 0;

  for (const row of rows) {
    // 2. Look up pending_member by contractNumber
    const snap = await db.collection('pending_members').where('contractNumber', '==', row.contrat).limit(1).get();
    if (snap.empty) {
      notFound++;
      continue;
    }

    const ins = snap.docs[0].data();
    const cin = ins.cin || '';
    if (!cin.trim()) {
      skipped++;
      continue;
    }

    // 3. Update SQLite
    try {
      cacheDb.prepare('UPDATE register_cache SET cin = ? WHERE id = ? AND gym_id = ?').run(cin.trim(), row.id, row.gym_id);
    } catch (e) {
      console.error(`SQLite update failed for contract ${row.contrat}: ${e.message}`);
    }

    // 4. Update Firestore if we have the entry ID
    try {
      const docRef = db.collection('megafit_daily_register')
        .doc(`${row.gym_id}_${row.date}`)
        .collection('entries')
        .doc(row.id);
      await docRef.update({ cin: cin.trim() });
    } catch (e) {
      console.warn(`Firestore update failed for ${row.contrat}: ${e.message}`);
    }

    console.log(`✅ Fixed CIN for contract ${row.contrat} (${row.nom}): ${cin}`);
    fixed++;
  }

  console.log(`\nDone. Fixed: ${fixed}, Skipped (no CIN in pending): ${skipped}, Not found: ${notFound}`);
  process.exit(0);
}

run().catch(e => { console.error(e); process.exit(1); });
