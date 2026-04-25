const admin = require('firebase-admin');
const path = require('path');

const serviceAccount = require(path.join(__dirname, 'serviceAccount.json'));
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

async function fixParent() {
  const docId = 'marjane_2026-04-23';
  await db.collection('megafit_daily_register').doc(docId).set({
    date: '2026-04-23',
    gymId: 'marjane',
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
  console.log('Fixed parent doc!');
  process.exit(0);
}

fixParent().catch(console.error);
