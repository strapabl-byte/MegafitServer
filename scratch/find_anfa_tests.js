
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function findAnfaTests() {
  console.log('🔍 Searching for members with location casa1 or anfa...');
  const gyms = ['casa1', 'anfa', 'Anfa', 'Casa Anfa'];
  
  for (const gym of gyms) {
    const snap = await db.collection('members').where('location', '==', gym).get();
    console.log(`- Found ${snap.size} members with location "${gym}"`);
    snap.forEach(doc => {
      const d = doc.data();
      console.log(`  [DELETE?] ${doc.id}: ${d.fullName || d.name + ' ' + d.surname}`);
    });
  }

  console.log('\n🔍 Searching for pending_members with gymId casa1 or anfa...');
  for (const gym of gyms) {
    const snap = await db.collection('pending_members').where('gymId', '==', gym).get();
    console.log(`- Found ${snap.size} pending with gymId "${gym}"`);
    snap.forEach(doc => {
      const d = doc.data();
      console.log(`  [DELETE?] ${doc.id}: ${d.prenom} ${d.nom}`);
    });
  }

  process.exit(0);
}

findAnfaTests();
