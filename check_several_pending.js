const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  const contracts = ['016054', '016052', '016048', '016066', '016056'];
  for (const c of contracts) {
    const snap = await db.collection('pending_members').where('contractNumber', '==', c).get();
    if (snap.empty) {
      console.log(`Contract ${c} not found in pending_members`);
    } else {
      snap.forEach(doc => {
        const d = doc.data();
        console.log(`Pending: contract=${c} | Nom=${d.nom} | CIN=${d.cin} | status=${d.status}`);
      });
    }
  }
}

run().catch(console.error);
