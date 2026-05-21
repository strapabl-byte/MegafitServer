const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  const doc = await db.collection('pending_members').doc('OrDOOKRbLulWlOxODX5Y').get();
  if (doc.exists) {
    const d = doc.data();
    console.log(`Pending doc OrDOOKRbLulWlOxODX5Y: nom="${d.nom}", prenom="${d.prenom}", cin="${d.cin}", contract="${d.contractNumber}", status="${d.status}"`);
  } else {
    console.log('Pending doc OrDOOKRbLulWlOxODX5Y not found');
  }
}

run().catch(console.error);
