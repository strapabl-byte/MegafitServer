
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

const TEST_NAMES = [
  'Wael Bouchaib',
  'Rania Tazi',
  'Souleiman Idrissi',
  'Hoda Bouzid',
  'Ali Rami',
  'Noura Sekkat',
  'Mustapha Chafik'
];

async function cleanupTestUsers() {
  console.log('🧹 Starting cleanup of specific test users...');

  for (const name of TEST_NAMES) {
    console.log(`\n🔍 Searching for "${name}"...`);

    // 1. Search in members
    const memberSnap = await db.collection('members')
      .where('fullName', '==', name)
      .get();
    
    // Also search by name/surname split if needed
    const nameParts = name.split(' ');
    const first = nameParts[0];
    const last = nameParts.slice(1).join(' ');
    
    const memberSnap2 = await db.collection('members')
      .where('name', '==', first)
      .where('surname', '==', last)
      .get();

    const allMemberDocs = [...memberSnap.docs, ...memberSnap2.docs];
    console.log(`- Found ${allMemberDocs.length} member records.`);

    for (const doc of allMemberDocs) {
      const data = doc.data();
      console.log(`  Deleting member ${doc.id} (Gym: ${data.location || data.gymId || 'unknown'})`);
      
      // Delete payments for this member
      const paySnap = await db.collection('payments').where('memberId', '==', doc.id).get();
      console.log(`  - Deleting ${paySnap.size} associated payments.`);
      for (const pDoc of paySnap.docs) await pDoc.ref.delete();

      await doc.ref.delete();
    }

    // 2. Search in pending_members (Inscriptions)
    const pendingSnap = await db.collection('pending_members')
      .where('nom', '==', last)
      .where('prenom', '==', first)
      .get();
    
    console.log(`- Found ${pendingSnap.size} pending inscriptions.`);
    for (const doc of pendingSnap.docs) {
      console.log(`  Deleting pending member ${doc.id}`);
      await doc.ref.delete();
    }
  }

  console.log('\n✅ Cleanup of specific test users complete.');
  process.exit(0);
}

cleanupTestUsers().catch(err => {
  console.error('❌ Cleanup failed:', err);
  process.exit(1);
});
