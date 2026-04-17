const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-05";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "14213", commercial: "REDA", nom: "EL KHOLTE YASMINE", cin: "CD770957", tel: "656601313", tpe: 0, espece: 0, virement: 0, cheque: 4000, abonnement: "2 ANS", note_reste: "COMP 24MOIS" },
    { contrat: "14083", commercial: "AHLAM", nom: "ILHAM CHOUMI", cin: "GA28833", tel: "666240685", tpe: 0, espece: 0, virement: 0, cheque: 3900, abonnement: "2 ANS", note_reste: "COMP 24MOIS" },
    { contrat: "14218", commercial: "SABER", nom: "OURAHOU CHAIMAE", cin: "AD233988", tel: "604422585", tpe: 3600, espece: 0, virement: 0, cheque: 0, abonnement: "6 MOIS" },
    { contrat: "14219", commercial: "SABER", nom: "AICHA EL KESSIRI", cin: "CD964522", tel: "614904720", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "3 MOIS" },
    { contrat: "14221", commercial: "SABER", nom: "MOHAMED BORJ", cin: "C772377", tel: "657859304", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV" },
    { contrat: "14222", commercial: "REDA", nom: "KMOUH MOHAMMED", cin: "C512365", tel: "663147092", tpe: 0, espece: 2500, virement: 0, cheque: 3400, abonnement: "AUTRE", note_reste: "OFFRE SAINT VALENTIN" }
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
