const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  console.log('Searching payments for fz0tFm87WsALISMUwMvP...');
  const snap = await db.collection('payments').where('memberId', '==', 'fz0tFm87WsALISMUwMvP').get();
  snap.forEach(doc => {
    const d = doc.data();
    console.log(`Payment: ID=${doc.id} | amount=${d.amount} | type=${d.type} | method=${d.method} | date=${d.date} | inscriptionId=${d.inscriptionId}`);
  });

  console.log('Searching payments for inscription OrDOOKRbLulWlOxODX5Y...');
  const snap2 = await db.collection('payments').where('inscriptionId', '==', 'OrDOOKRbLulWlOxODX5Y').get();
  snap2.forEach(doc => {
    const d = doc.data();
    console.log(`Payment by InsId: ID=${doc.id} | amount=${d.amount} | type=${d.type} | method=${d.method} | date=${d.date}`);
  });
}

run().catch(console.error);
