const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const gymId = 'marjane';

async function fixFields(date) {
  const docId = `${gymId}_${date}`;
  const snap = await db.collection('megafit_daily_register').doc(docId).collection('entries').get();
  
  for (const doc of snap.docs) {
    const data = doc.data();
    const updates = {};
    
    // Map wrong keys to right keys
    if (data.n_contrat !== undefined) { updates.contrat = data.n_contrat; updates.n_contrat = admin.firestore.FieldValue.delete(); }
    if (data.name !== undefined) { updates.nom = data.name; updates.name = admin.firestore.FieldValue.delete(); }
    if (data.num_tel !== undefined) { updates.tel = data.num_tel; updates.num_tel = admin.firestore.FieldValue.delete(); }
    if (data.av_comp !== undefined) { updates.abonnement = data.av_comp; updates.av_comp = admin.firestore.FieldValue.delete(); }
    
    if (Object.keys(updates).length > 0) {
      await doc.ref.update(updates);
      console.log(`Updated doc ${doc.id} on ${date}`);
    }
  }
}

async function run() {
  console.log('Fixing fields...');
  try {
    await fixFields('2026-04-18');
    await fixFields('2026-04-19');
    console.log('✅ Fix complete!');
    process.exit(0);
  } catch (e) {
    console.error('Error fixing records:', e);
    process.exit(1);
  }
}

run();
