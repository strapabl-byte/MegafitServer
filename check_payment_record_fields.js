const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  const doc = await db.collection('payments').doc('tr53h4rEwtoY4QOCyUFt').get();
  if (doc.exists) {
    console.log(JSON.stringify(doc.data(), null, 2));
  } else {
    console.log('Payment doc tr53h4rEwtoY4QOCyUFt not found');
  }
}

run().catch(console.error);
