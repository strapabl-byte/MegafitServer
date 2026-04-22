const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

async function run() {
  const snap = await db.collection('courses')
    .where('createdBy', '==', 'Auto-Seeder-Kids')
    .get();

  if (snap.empty) { console.log('No kids courses found.'); process.exit(0); }

  const batch = db.batch();
  snap.docs.forEach(doc => batch.delete(doc.ref));
  await batch.commit();
  console.log(`✅ Deleted ${snap.docs.length} kids courses from the main courses collection.`);
  process.exit(0);
}
run().catch(console.error);
