const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const WRONG_DOC = 'dokarat_2026-04-21';
const CORRECT_DOC = 'marjane_2026-04-21';

const targetNames = [
  "MOHAMED ABIDAR",
  "TIRGHZA OMAR",
  "BENADADA ASMAE",
  "essdik bensedik",
  "EL BAKALI MAROUANE",
  "KASRI MONCEF",
  "EL MAAZOUZI ANAS"
].map(n => n.toLowerCase());

async function run() {
  try {
    const wrongRef = db.collection('megafit_daily_register').doc(WRONG_DOC).collection('entries');
    const correctRef = db.collection('megafit_daily_register').doc(CORRECT_DOC).collection('entries');

    const snap = await wrongRef.get();
    
    let moved = 0;
    for (const doc of snap.docs) {
      const data = doc.data();
      if (data.nom && targetNames.includes(String(data.nom).trim().toLowerCase())) {
          console.log(`Moving ${data.nom} to Marjane...`);
          await correctRef.add(data);
          await doc.ref.delete();
          moved++;
      }
    }

    // Ensure parent doc exists for Marjane
    await db.collection('megafit_daily_register').doc(CORRECT_DOC).set({
        gymId: 'marjane',
        date: '2026-04-21',
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log(`\n✅ Finished! Moved ${moved} entries from Dokarat to Marjane.`);
    process.exit(0);
  } catch (err) {
    console.error("Error:", err);
    process.exit(1);
  }
}

run();
