const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

if (admin.apps.length === 0) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-15";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "14314", commercial: "AHLAM", nom: "ERJATI KAOUTAR", cin: "CB291917", tel: "668806234", tpe: 1500, espece: 0, virement: 0, cheque: 0, abonnement: "CARNET ENTREE 20", note_reste: "CARNET 20 TICKETS" },
    { contrat: "14315", commercial: "REDA", nom: "SOUFIANE ALAMI", cin: "NHL11080", tel: "", tpe: 700, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "2 SEMAINE" },
    { contrat: "14316", commercial: "-", nom: "MEFTOUKI KAWTAR", cin: "C944291", tel: "662787309", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "", commercial: "SABER", nom: "AMAL EL MIDAOUI", cin: "", tel: "", tpe: 0, espece: 0, virement: 1000, cheque: 0, abonnement: "AUTRE", note_reste: "COMP COACHING" },
    { contrat: "14317", commercial: "REDA", nom: "EL GUZOULI MOHAMMED", cin: "CD236603", tel: "661924256", tpe: 0, espece: 3000, virement: 0, cheque: 2900, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14318", commercial: "AHLAM", nom: "MOUHSINE AHMED", cin: "CD185212", tel: "661439229", tpe: 0, espece: 0, virement: 0, cheque: 5900, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" }
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
    
    console.log("✨ Day 15 Import Complete!");
    process.exit(0);
}

run().catch(err => {
    console.error("❌ Fatal error:", err);
    process.exit(1);
});
