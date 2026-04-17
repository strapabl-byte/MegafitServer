const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

if (admin.apps.length === 0) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const gymId = "marjane"; 
const dateStr = "2026-04-13";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "14248", commercial: "AHLAM", nom: "MPOKAMA NANENGO", cin: "POO214324", tel: "", tpe: 0, espece: 800, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "3 SEMAINE" },
    { contrat: "", commercial: "AHLAM", nom: "BENJELLOUN SANAE", cin: "", tel: "613446126", tpe: 2000, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COACHING HANANE" },
    { contrat: "14249", commercial: "SABER", nom: "BENNANI ABDELAZIZ", cin: "", tel: "", tpe: 0, espece: 0, virement: 0, cheque: 3600, abonnement: "1 AN", note_reste: "CONVENTION ATTIJARI 12 MOIS" },
    { contrat: "", commercial: "REDA", nom: "IMADE BENKIRANE", cin: "", tel: "", tpe: 0, espece: 500, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COMP COACHING" },
    { contrat: "28001", commercial: "REDA", nom: "HABYBY AMAL", cin: "", tel: "", tpe: 600, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COACHING 20 ( YOUSSRA )" },
    { contrat: "14301", commercial: "SABER", nom: "MIARA ADNANE", cin: "CD555819", tel: "668786758", tpe: 0, espece: 2100, virement: 3800, cheque: 0, abonnement: "2 ANS", note_reste: "" },
    { contrat: "14302", commercial: "AHLAM", nom: "SKOURI KARIM", cin: "", tel: "777155242", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS", note_reste: "" },
    { contrat: "14303", commercial: "AHLAM", nom: "KERROUMI HAMZA", cin: "CB327271", tel: "651128297", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS", note_reste: "" },
    { contrat: "14250", commercial: "SABER", nom: "BEKKALI GHITA", cin: "CD388429", tel: "671305095", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS", note_reste: "" }
];

async function run() {
    console.log(`🚀 Starting import for ${gymId} on ${dateStr}`);
    
    // Ensure parent doc exists
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
    
    console.log("✨ Day 13 Import Complete!");
    process.exit(0);
}

run().catch(err => {
    console.error("❌ Fatal error:", err);
    process.exit(1);
});
