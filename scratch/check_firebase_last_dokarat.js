const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

(async () => {
  // First: list all top-level collections to find the right one
  const cols = await db.listCollections();
  console.log('📁 Collections in Firestore:');
  cols.forEach(c => console.log(' -', c.id));

  // Try the most likely collection names
  const candidates = ['door_entries', 'entries', 'doorEntries', 'dokarat_entries', 'megafit_entries'];
  for (const colName of candidates) {
    try {
      const snap = await db.collection(colName).limit(1).get();
      if (!snap.empty) {
        console.log(`\n✅ Found data in collection: "${colName}"`);
        console.log('Sample doc:', { id: snap.docs[0].id, ...snap.docs[0].data() });
      }
    } catch (e) {
      // skip
    }
  }
  process.exit(0);
})();
