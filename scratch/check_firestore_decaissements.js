const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

// Initialize Firebase Admin SDK if not already initialized
if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function checkFirestore() {
  const date = '2026-05-22';
  const gyms = ['dokarat', 'marjane', 'casa1', 'casa2'];

  console.log(`Checking Firestore for decaissements on ${date}...`);

  for (const gid of gyms) {
    const docId = `${gid}_${date}`;
    const snap = await db.collection('megafit_daily_register')
                         .doc(docId)
                         .collection('decaissements')
                         .get();

    if (!snap.empty) {
      console.log(`\nGym: ${gid} (Firestore has ${snap.size} decaissements):`);
      snap.forEach(doc => {
        console.log(JSON.stringify({
          id: doc.id,
          ...doc.data()
        }, null, 2));
      });
    } else {
      console.log(`Gym: ${gid} - No decaissements on Firestore`);
    }
  }
}

checkFirestore().catch(console.error);
