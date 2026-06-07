const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function run() {
  const gyms = ['dokarat', 'marjane', 'casa1', 'casa2', 'rabat', 'kenitra'];
  const date = '2026-05-20';
  console.log(`Fetching Firestore daily register entries for ${date}...`);
  for (const gymId of gyms) {
    const docId = `${gymId}_${date}`;
    const snap = await db.collection('megafit_daily_register').doc(docId).collection('entries').get();
    if (!snap.empty) {
      console.log(`\nGym: ${gymId} (${snap.size} entries):`);
      snap.forEach(doc => {
        const d = doc.data();
        console.log(`  - ID: ${doc.id} | nom: "${d.nom}" | cin: "${d.cin}" | contrat: "${d.contrat}" | source: "${d.source}"`);
      });
    }
  }
}

run().catch(console.error);
