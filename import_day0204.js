const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-02";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "", commercial: "SABER", nom: "HARY SAVER", cin: "", tel: "", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "ACCES JOURNALIER" },
    { contrat: "", commercial: "SABER", nom: "TIMO WINTERSTIEN", cin: "", tel: "", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "ACCES JOURNALIER" },
    { contrat: "14082", commercial: "AHLAM", nom: "ALAOUI MDAGHRI HACHEM", cin: "CD204829", tel: "653445586", tpe: 0, espece: 3900, virement: 0, cheque: 0, abonnement: "COMP SAINT VALENTIN" },
    { contrat: "14100", commercial: "REDA", nom: "KARIM DOUIRI", cin: "-18", tel: "780641095", tpe: 0, espece: 1000, virement: 0, cheque: 0, abonnement: "AV SAINT VALENTIN" },
    { contrat: "", commercial: "AHLAM", nom: "GHANIA DRIOUCH", cin: "", tel: "", tpe: 0, espece: 1000, virement: 0, cheque: 0, abonnement: "COMP" },
    { contrat: "14099", commercial: "REDA", nom: "SELOUA TMER", cin: "CD702329", tel: "777008148", tpe: 0, espece: 4000, virement: 0, cheque: 0, abonnement: "AV PROMO SAINT VALENTIN" },
    { contrat: "14098", commercial: "REDA", nom: "LACHCHAB WAHIB", cin: "C499842", tel: "662625809", tpe: 0, espece: 0, virement: 0, cheque: 5900, abonnement: "AUTRE" }, // PROMO SAINT VALENTIN mapped to AUTRE per notes
    { contrat: "14201", commercial: "REDA", nom: "TARIK ACHEFFANE", cin: "C949073", tel: "661937423", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "AUTRE" }  // PROMO SAINT VALENTIN mapped to AUTRE per notes
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
            note_reste: (entry.abonnement === "AUTRE") ? "PROMO SAINT VALENTIN" : "",
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
