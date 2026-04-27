const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function check() {
  const snap = await db.collection('members').get();
  const weird = snap.docs.map(d => ({id: d.id, ...d.data()})).filter(m => {
    return (!m.fullName || m.fullName.trim().length === 0) && !m.isArchive;
  });
  console.log('Weird members found:', weird.length);
  console.log(JSON.stringify(weird.slice(0, 10), null, 2));
}

check();
