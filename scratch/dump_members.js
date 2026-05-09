
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function listAllMembers() {
  console.log('📋 Dumping ALL member names in Firestore (limit 500):');
  const snap = await db.collection('members').limit(500).get();
  snap.forEach(doc => {
    const d = doc.data();
    console.log(`- ${d.fullName || d.name + ' ' + d.surname}`);
  });
  process.exit(0);
}

listAllMembers();
