const admin = require('firebase-admin');
const lc = require('./localCache.js');
const serviceAccount = require('./serviceAccount.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

async function backfill() {
  console.log('Fetching ALL pending_members from Firebase (full backfill)...');
  const snap = await db.collection('pending_members').get();
  let count = 0;
  snap.forEach(doc => {
    const data = doc.data();
    lc.setPending({ id: doc.id, ...data });
    count++;
  });
  console.log(`✅ Full backfill complete: ${count} records written to SQLite pending_cache!`);
  
  // Quick verification
  const withPhone = lc.db.prepare('SELECT COUNT(*) as cnt FROM pending_cache WHERE telephone IS NOT NULL').get();
  console.log(`📱 Records with phone: ${withPhone.cnt}`);
  const withBday = lc.db.prepare('SELECT COUNT(*) as cnt FROM pending_cache WHERE date_naissance IS NOT NULL').get();
  console.log(`🎂 Records with birthday: ${withBday.cnt}`);
  process.exit(0);
}

backfill().catch(err => { console.error(err); process.exit(1); });
