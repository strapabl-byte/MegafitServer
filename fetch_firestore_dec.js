require('dotenv').config();
const admin = require('firebase-admin');

if (!admin.apps.length) {
  const sa = require('./serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(sa) });
}
const db = admin.firestore();

async function main() {
  const gymId = 'dokarat';
  const year  = '2026';
  const month = '04';

  let totalDec = 0;
  const allDec = [];

  // Iterate all April days
  for (let d = 1; d <= 30; d++) {
    const dateStr = `${year}-${month}-${String(d).padStart(2,'0')}`;
    const docRef  = db.collection('megafit_daily_register').doc(`${gymId}_${dateStr}`);
    const decSnap = await docRef.collection('decaissements').get();
    if (!decSnap.empty) {
      decSnap.docs.forEach(doc => {
        const dec = doc.data();
        allDec.push({ date: dateStr, ...dec });
        totalDec += Number(dec.montant || 0);
        console.log(dateStr, '→', dec.montant, 'DH |', dec.raison || '', '| status:', dec.status || 'none');
      });
    }
  }

  console.log('\n=== TOTAL décaissements in Firestore (Dokarat April) ===');
  console.log('Count:', allDec.length);
  console.log('Total:', totalDec.toLocaleString(), 'DH');
  console.log('\nExpected: 18,000 DH');
  console.log('Difference:', totalDec - 18000, 'DH');
  
  process.exit(0);
}
main().catch(e => { console.error(e); process.exit(1); });
