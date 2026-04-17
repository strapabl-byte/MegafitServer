const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-04";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "13803", commercial: "REDA", nom: "KANJA NABIL", cin: "K116401", tel: "661229037", tpe: 0, espece: 8500, virement: 0, cheque: 0, abonnement: "2 ANS", note_reste: "COMP 24 MOIS + 20 COACHING ( khalll )" },
    { contrat: "14212", commercial: "REDA", nom: "ASSERMOUH ALEXANDRA", cin: "", tel: "33616095275", tpe: 800, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "3 SEMAINE" },
    { contrat: "14210", commercial: "REDA", nom: "ASSERNOUH REDOUANE", cin: "", tel: "33616095275", tpe: 100, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COMP 3 SEMAINE" },
    { contrat: "14214", commercial: "AHLAM", nom: "SALMA TOUILB", cin: "CD265397", tel: "666973385", tpe: 350, espece: 2400, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV PROMO SAINT VALENTIN" },
    { contrat: "14215", commercial: "AHLAM", nom: "BENZARI MOHAMED", cin: "CD234242", tel: "699348363", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS" },
    { contrat: "14207", commercial: "AHLAM", nom: "AMMOUR BOUBKER", cin: "C368975", tel: "661357873", tpe: 0, espece: 950, virement: 0, cheque: 4000, abonnement: "2 ANS", note_reste: "COMP 24 MOIS" },
    { contrat: "14206", commercial: "SABER", nom: "AMMOUR MOHAMMED", cin: "C368975", tel: "679676761", tpe: 0, espece: 950, virement: 0, cheque: 4000, abonnement: "2 ANS", note_reste: "COMP 24 MOIS" },
    { contrat: "14216", commercial: "REDA", nom: "AFEKHSI EL GHALI", cin: "CD950737", tel: "705926455", tpe: 1475, espece: 0, virement: 0, cheque: 4425, abonnement: "2 ANS" },
    { contrat: "14217", commercial: "REDA", nom: "AFEKHSI MOHAMMED", cin: "C456367", tel: "663832312", tpe: 1475, espece: 0, virement: 0, cheque: 4425, abonnement: "2 ANS" },
    { contrat: "14213", commercial: "REDA", nom: "EL KHOLTE YASMINE", cin: "CD770957", tel: "656601313", tpe: 0, espece: 1900, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV PROMO SAINT VALENTIN" }
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
