
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function listPending() {
  console.log('📋 Dumping ALL pending_members names (limit 1000):');
  const snap = await db.collection('pending_members').get();
  snap.forEach(doc => {
    const d = doc.data();
    console.log(`- ${doc.id}: ${d.prenom} ${d.nom} (${d.gymId})`);
  });
  process.exit(0);
}

listPending();
