const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const GYM_ID = 'dokarat';
const DATE = '2026-04-18';
const DOC_ID = `${GYM_ID}_${DATE}`;

// The exact 12 entries from the screenshot
const screenshotData = [
  { contrat: "14366", commercial: "HAJAR", nom: "MERROUNI ISMAIL", cin: "C945250", tel: "661389330", tpe: 0, espece: 0, virement: 0, cheque: 1500, abonnement: "1 AN CNV CRIDIT AGRICOLE" },
  { contrat: "14368", commercial: "OUISSALE", nom: "RABIA BOUHAFS", cin: "-", tel: "694365862", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2ANS S/V" },
  { contrat: "14367", commercial: "HAJAR", nom: "AZIZ RAJAE", cin: "-", tel: "662082763", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2ANS S/V" },
  { contrat: "14369", commercial: "OUISSALE", nom: "ABDELLAH OUBOUQSSI", cin: "CD973144", tel: "614766169", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2ANS S/V" },
  { contrat: "", commercial: "IMANE", nom: "HICHAM BENABDELHAFID", cin: "PY825081", tel: "762638996", tpe: 0, espece: 1000, virement: 0, cheque: 0, abonnement: "CARNIER D'ENTREE JOURNALIER" },
  { contrat: "14363", commercial: "HAJAR", nom: "FATIMAZAHRA FARAES", cin: "CC27288", tel: "666600365", tpe: 0, espece: 0, virement: 0, cheque: 3900, abonnement: "COM DE 2 ANS" },
  { contrat: "14370", commercial: "OUISSALE", nom: "NEZHA EL ARABI", cin: "CD302467", tel: "604868131", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "" },
  { contrat: "14352", commercial: "HAJAR", nom: "BOULAGHMOUD MOSTAFA", cin: "CD104746", tel: "661671240", tpe: 0, espece: 2300, virement: 0, cheque: 0, abonnement: "COM DE 2 ANS" },
  { contrat: "14371", commercial: "HAJAR", nom: "BADAR ASMAR", cin: "C347245", tel: "661997902", tpe: 0, espece: 0, virement: 0, cheque: 6900, abonnement: "2 ANS S/V" },
  { contrat: "14372", commercial: "OUISSALE", nom: "ABDELHAK MAGHRANE", cin: "CD671475", tel: "682672940", tpe: 0, espece: 0, virement: 0, cheque: 6900, abonnement: "2 ANS S/V" },
  { contrat: "14373", commercial: "IMANE", nom: "YASSER HILALI", cin: "-", tel: "707282680", tpe: 0, espece: 2200, virement: 0, cheque: 0, abonnement: "3 MOIS" },
  { contrat: "14374", commercial: "IMANE", nom: "YOUSSEF EL SHODDANI", cin: "C198582", tel: "666742048", tpe: 5600, espece: 0, virement: 0, cheque: 0, abonnement: "2ANS S/V" },
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
