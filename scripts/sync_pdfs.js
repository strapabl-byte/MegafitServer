const Database = require('better-sqlite3');
const path = require('path');
const admin = require('firebase-admin');
const fs = require('fs');

if (!fs.existsSync(path.join(__dirname, 'serviceAccount.json'))) {
  console.log("No admin sdk, skipping firestore sync.");
  process.exit(0);
}

admin.initializeApp({
  credential: admin.credential.cert(require('./serviceAccount.json')),
  storageBucket: "megafitauth.appspot.com"
});

const DB_PATH = path.join(__dirname, 'megafit_cache.db');
const db = new Database(DB_PATH);

try { db.exec("ALTER TABLE pending_cache ADD COLUMN pdf_url TEXT;"); } catch (e) {
  console.log("Column exists or error:", e.message);
}

async function syncPdfs() {
  const snap = await admin.firestore().collection('pending_members').get();
  let count = 0;
  snap.forEach(doc => {
    const data = doc.data();
    if (data.pdfUrl || data.pdf_url) {
      db.prepare("UPDATE pending_cache SET pdf_url = ? WHERE id = ?").run(data.pdfUrl || data.pdf_url, doc.id);
      count++;
    }
  });
  console.log(`✅ Synced ${count} pdf_urls to pending_cache`);
  process.exit(0);
}

syncPdfs();
