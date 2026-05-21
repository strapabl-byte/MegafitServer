const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  const Database = require('better-sqlite3');
  const cacheDb = new Database('megafit_cache.db');
  
  // Note: 'source' column is not in register_cache schema, so we can't filter by e.source since it's not a SQLite column!
  // Wait, let's verify if the SQLite schema has a source column.
  // We printed the schema earlier:
  // - id, gym_id, date, nom, contrat, commercial, tpe, espece, virement, cheque, abonnement, created_at, synced_at, cin, tel, prix, reste, note_reste.
  // There is NO source column in SQLite! So we can't filter by source.
  // But we can check which entries on date >= '2026-05-18' have CIN.
  const entries = cacheDb.prepare("SELECT * FROM register_cache WHERE date >= '2026-05-18' ORDER BY date DESC, created_at DESC").all();
  console.log(`Recent entries (since May 18th):`);
  entries.forEach(e => {
    console.log(`- Date: ${e.date} | Contract: ${e.contrat} | Nom: ${e.nom} | CIN: "${e.cin}"`);
  });
}

run().catch(console.error);
