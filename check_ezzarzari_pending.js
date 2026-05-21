const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  console.log('Searching pending_members for EZZARZARI...');
  const snap1 = await db.collection('pending_members').where('nom', '==', 'EZZARZARI').get();
  snap1.forEach(doc => {
    console.log(`Pending: ID=${doc.id}, nom=${doc.data().nom}, prenom=${doc.data().prenom}, contract=${doc.data().contractNumber}, cin=${doc.data().cin}, status=${doc.data().status}`);
  });

  console.log('Searching pending_members for Yourdane...');
  const snap2 = await db.collection('pending_members').where('nom', '==', 'Yourdane').get();
  snap2.forEach(doc => {
    console.log(`Pending: ID=${doc.id}, nom=${doc.data().nom}, prenom=${doc.data().prenom}, contract=${doc.data().contractNumber}, cin=${doc.data().cin}, status=${doc.data().status}`);
  });
}

run().catch(console.error);
