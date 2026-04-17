const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-03";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "14203", commercial: "AHLAM", nom: "IMANE NAJID", cin: "C942806", tel: "661776575", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS" },
    { contrat: "", commercial: "AHLAM", nom: "SADEQI MASRAR", cin: "", tel: "", tpe: 3600, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COACHING AVEC MOUHCINE" },
    { contrat: "", commercial: "SABER", nom: "AMAL EL MIDAOUI", cin: "CD727434", tel: "657519741", tpe: 0, espece: 1000, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV COACHING AVEC MOUHCINE" },
    { contrat: "14204", commercial: "AHLALM", nom: "BOUCHTATI MOHAMED", cin: "CD209222", tel: "663508325", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "TRANSFERT DEJA PAYE" },
    { contrat: "14207", commercial: "AHLAM", nom: "AMMOUR BOUBKER", cin: "CD185748", tel: "661357873", tpe: 0, espece: 950, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV" },
    { contrat: "14206", commercial: "SABER", nom: "AMMOUR MOHAMMED", cin: "C368975", tel: "679676761", tpe: 0, espece: 950, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV" },
    { contrat: "14205", commercial: "REDA", nom: "SEMLALI ALAE DINE", cin: "CD489070", tel: "652316689", tpe: 1600, espece: 0, virement: 0, cheque: 4300, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14208", commercial: "SABER", nom: "FATIMA KHALLOURFII", cin: "E128964", tel: "611377029", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14209", commercial: "SABER", nom: "IMANE EL KHAZANE", cin: "CB363746", tel: "621312958", tpe: 0, espece: 2500, virement: 0, cheque: 0, abonnement: "2 ANS" },
    { contrat: "14211", commercial: "AHLAM", nom: "OUKILI GARTI JABRANE", cin: "PS 806114", tel: "", tpe: 0, espece: 0, virement: 2000, cheque: 0, abonnement: "2 ANS" },
    { contrat: "14210", commercial: "REDA", nom: "ASSERNOUH REDOUANE", cin: "", tel: "33616095275", tpe: 700, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "2 SEMAINE" },
    { contrat: "13358", commercial: "REDA", nom: "RHORBA YOUNESS", cin: "", tel: "656658565", tpe: 1500, espece: 500, virement: 0, cheque: 0, abonnement: "2 ANS", note_reste: "COMP 24MOIS" }
];

async function run() {
    console.log(`🚀 Starting import for ${gymId} on ${dateStr}`);
    
    // 1. Ensure the parent document exists
    await db.collection('megafit_daily_register').doc(docId).set({
        gymId,
        date: dateStr,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    const entriesCol = db.collection('megafit_daily_register').doc(docId).collection('entries');
    
    for (const entry of entries) {
        const prix = (entry.tpe || 0) + (entry.espece || 0) + (entry.virement || 0) + (entry.cheque || 0);
        
        await entriesCol.add({
            ...entry,
            prix,
            reste: 0,
            source: 'manual_screenshot_import',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            createdBy: 'antigravity'
        });
        console.log(`✅ Added: ${entry.nom} (${prix} DH)`);
    }
    
    console.log("✨ Import complete!");
    process.exit(0);
}

run().catch(err => {
    console.error("❌ Fatal error:", err);
    process.exit(1);
});
