const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const GYM_ID = 'dokarat';
const DATE = '2026-04-21';
const DOC_ID = `${GYM_ID}_${DATE}`;

// The 7 entries from the screenshot for 21/04/2026
const screenshotData = [
  { contrat: "152", commercial: "REDA", nom: "MOHAMED ABIDAR", cin: "-", tel: "-", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "ACCES JOURNALIER" },
  { contrat: "153", commercial: "REDA", nom: "TIRGHZA OMAR", cin: "-", tel: "-", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "ACCES JOURNALIER" },
  { contrat: "14344", commercial: "REDA", nom: "BENADADA ASMAE", cin: "C351757", tel: "663116114", tpe: 0, espece: 0, virement: 0, cheque: 5900, abonnement: "PROMO SAINT VALENTIN" },
  { contrat: "-", commercial: "AHLAM", nom: "essdik bensedik", cin: "-", tel: "662501380", tpe: 0, espece: 0, virement: 1000, cheque: 0, abonnement: "AV COACHING" },
  { contrat: "14346", commercial: "AHLAM", nom: "EL BAKALI MAROUANE", cin: "cd471854", tel: "600688492", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "PROMO SAINT VALENTIN" },
  { contrat: "14345", commercial: "SABER", nom: "KASRI MONCEF", cin: "ZT221562", tel: "650400533", tpe: 0, espece: 2200, virement: 0, cheque: 0, abonnement: "3 MOIS" },
  { contrat: "14330", commercial: "REDA", nom: "EL MAAZOUZI ANAS", cin: "CD514099", tel: "771607483", tpe: 0, espece: 3300, virement: 0, cheque: 0, abonnement: "COMP" }
];

async function run() {
  try {
    const colRef = db.collection('megafit_daily_register').doc(DOC_ID).collection('entries');
    const existingSnap = await colRef.get();
    
    const existingNames = new Set(existingSnap.docs.map(d => String(d.data().nom).trim().toLowerCase()));
    
    let addedCount = 0;
    
    for (const item of screenshotData) {
      if (!existingNames.has(String(item.nom).trim().toLowerCase())) {
        console.log(`Missing entry detected: ${item.nom} - Adding...`);
        const payload = {
            ...item,
            tpe: String(item.tpe || ''),
            espece: String(item.espece || ''),
            virement: String(item.virement || ''),
            cheque: String(item.cheque || ''),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };
        await colRef.add(payload);
        addedCount++;
      } else {
        console.log(`Skipping ${item.nom} (Already exists)`);
      }
    }
    
    // Ensure the parent doc exists
    await db.collection('megafit_daily_register').doc(DOC_ID).set({
        gymId: GYM_ID,
        date: DATE,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log(`\n✅ Finished! Added ${addedCount} missing entry/entries.`);
    process.exit(0);
  } catch (err) {
    console.error("Error:", err);
    process.exit(1);
  }
}

run();
