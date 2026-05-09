
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function listCollections() {
  const collections = await db.listCollections();
  console.log('📚 Firestore Collections:');
  for (const coll of collections) {
    console.log(`- ${coll.id}`);
  }
  process.exit(0);
}

listCollections();
