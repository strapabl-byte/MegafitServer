
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function listMembers() {
  console.log('📋 Listing first 10 members in Firestore:');
  const snap = await db.collection('members').limit(10).get();
  snap.forEach(doc => {
    const d = doc.data();
    console.log(`- ${doc.id}: ${d.fullName || d.name + ' ' + d.surname} (${d.location})`);
  });
  
  console.log('\n📋 Listing first 10 pending_members in Firestore:');
  const snap2 = await db.collection('pending_members').limit(10).get();
  snap2.forEach(doc => {
    const d = doc.data();
    console.log(`- ${doc.id}: ${d.prenom} ${d.nom} (${d.gymId})`);
  });
  
  process.exit(0);
}

listMembers();
