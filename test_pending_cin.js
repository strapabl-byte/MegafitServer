const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function run() {
  console.log(`Dumping last 20 SQLite register_cache entries...`);
  const Database = require('better-sqlite3');
  const cacheDb = new Database('megafit_cache.db');
  
  const entries = cacheDb.prepare("SELECT * FROM register_cache ORDER BY created_at DESC LIMIT 20").all();
  console.log('SQLite Entries:', JSON.stringify(entries.map(e => ({ nom: e.nom, contrat: e.contrat, date: e.date, cin: e.cin, prix: e.prix })), null, 2));
}

run().catch(console.error);
