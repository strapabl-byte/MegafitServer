const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

if (admin.apps.length === 0) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const gymId = "marjane"; // Fès Saiss
const dateStr = "2026-04-14";
const docId = `${gymId}_${dateStr}`;

const entries = [
    { contrat: "14304", commercial: "SABER", nom: "ADADI AMINA", cin: "D818834", tel: "674647696", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14305", commercial: "SABER", nom: "AFAF BOUHOUTE", cin: "CD41667", tel: "610069155", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14306", commercial: "REDA", nom: "SECREF REMI", cin: "", tel: "", tpe: 800, espece: 0, virement: 0, cheque: 0, abonnement: "1 MOIS", note_reste: "1 MOIS VOISIN D REDA" },
    { contrat: "14307", commercial: "REDA", nom: "BEN BASSOU ASMAE", cin: "CD378171", tel: "648390505", tpe: 0, espece: 0, virement: 1000, cheque: 0, abonnement: "1 MOIS", note_reste: "REABO 1MOIS" },
    { contrat: "14308", commercial: "REDA", nom: "KHAYET OUSSAMA", cin: "EE601765", tel: "660138700", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14309", commercial: "REDA", nom: "ABDELLAH MOUKHLISS", cin: "C332125", tel: "661216316", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14311", commercial: "REDA", nom: "ASSERMOUH WISSAM", cin: "", tel: "", tpe: 0, espece: 500, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "7JOURS" },
    { contrat: "14313", commercial: "REDA", nom: "ABDELLA AHMED", cin: "CD295936", tel: "661902320", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14312", commercial: "REDA", nom: "ABBOUSS BADIA", cin: "C433672", tel: "61188435", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14310", commercial: "REDA", nom: "EL BAKIOUI FATIMA", cin: "R312614", tel: "661919131", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
    { contrat: "14088", commercial: "REDA", nom: "BENSAD KAOUTAR", cin: "CD512489", tel: "681315595", tpe: 0, espece: 3000, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COMP" }
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
    
    console.log("✨ Day 14 Import Complete!");
    process.exit(0);
}

run().catch(err => {
    console.error("❌ Fatal error:", err);
    process.exit(1);
});
