const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const DOC_ID = 'dokarat_2026-04-18';

async function check() {
  const snap = await db.collection('megafit_daily_register').doc(DOC_ID).collection('entries').get();
  console.log(`\n--- Verification for ${DOC_ID} ---\n`);
  console.log(`Found ${snap.size} total entries.\n`);
  
  snap.docs.forEach((doc, i) => {
    const d = doc.data();
    console.log(`${i+1}. NOM: ${d.nom} | CONTRAT: ${d.contrat} | CHEQUE/TPE/ESP/VIR: ${d.cheque || 0}/${d.tpe || 0}/${d.espece || 0}/${d.virement || 0}`);
  });
  
  console.log('\n✅ Verification Complete.');
  process.exit(0);
}

check();
