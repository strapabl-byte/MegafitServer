
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function searchCasa1() {
  const collections = ['members', 'payments', 'registers', 'registrations', 'courses', 'pending_members', 'stats'];
  console.log('🔍 Searching for documents with gymId = "casa1" across collections...');

  for (const collName of collections) {
    try {
      const snap = await db.collection(collName).where('gymId', '==', 'casa1').get();
      if (snap.empty) {
        console.log(`- ${collName}: 0 found`);
      } else {
        console.log(`- ${collName}: ${snap.size} found!`);
        snap.forEach(doc => {
          console.log(`  [${collName}] ID: ${doc.id} - Data: ${JSON.stringify(doc.data()).substring(0, 100)}...`);
        });
      }
    } catch (e) {
      console.log(`- ${collName}: Error ${e.message}`);
    }
  }
  process.exit(0);
}

searchCasa1();
