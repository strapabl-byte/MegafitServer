const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-06";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "14211", commercial: "AHLAM", nom: "OUKILI GARTI JABRANE", cin: "PS806114", tel: "", tpe: 0, espece: 0, virement: 0, cheque: 3900, abonnement: "2 ANS", note_reste: "COMP 24 MOIS" },
    { contrat: "", commercial: "REDA", nom: "MANAL MANSOURI", cin: "", tel: "", tpe: 0, espece: 1500, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COMP" },
    { contrat: "14233", commercial: "AHLAM", nom: "EL IDRISSI MOHAMED", cin: "S61022", tel: "", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS", note_reste: "24MOIS" },
    { contrat: "14224", commercial: "REDA", nom: "omar ait qadi", cin: "CD610622", tel: "", tpe: 2200, espece: 0, virement: 0, cheque: 0, abonnement: "3 MOIS", note_reste: "3MOIS" }
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
