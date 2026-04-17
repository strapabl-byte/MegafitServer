const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

if (admin.apps.length === 0) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const gymId = "marjane"; // Fès Saiss

const dataByDay = {
    "2026-04-07": [
        { contrat: "14225", commercial: "REDA", nom: "DOUNIA ASSERMOUH", cin: "M120NHOK5", tel: "", tpe: 700, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "2 SEMAINE" },
        { contrat: "14226", commercial: "AHLAM", nom: "ZAIM YOUNES", cin: "OS800219", tel: "4794282111", tpe: 0, espece: 2200, virement: 0, cheque: 0, abonnement: "3 MOIS" },
        { contrat: "14227", commercial: "SABER", nom: "NAJT MGATAA", cin: "", tel: "671416613", tpe: 0, espece: 2200, virement: 0, cheque: 0, abonnement: "3 MOIS" },
        { contrat: "14099", commercial: "REDA", nom: "SELOUA TMER", cin: "CD702329", tel: "777008148", tpe: 0, espece: 0, virement: 0, cheque: 1900, abonnement: "AUTRE", note_reste: "COMP PROMO SAINT VALENTIN" }
    ],
    "2026-04-08": [
        { contrat: "14228", commercial: "SABER", nom: "ZOUITNI ABDELMOUNIM", cin: "CD5487", tel: "671304172", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS", note_reste: "REABO 24MOIS" },
        { contrat: "14229", commercial: "AHLAM", nom: "BAALLA KARIMA", cin: "DA73165", tel: "681270873", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS" }
    ],
    "2026-04-09": [
        { contrat: "14230", commercial: "SARAH", nom: "SAMOUH NADIA", cin: "C169588", tel: "66481894", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS" },
        { contrat: "14231", commercial: "SARAH", nom: "ABDELKADER BENCHEIKH", cin: "PW807765", tel: "682670520", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS" },
        { contrat: "12619", commercial: "REDA", nom: "DALYLA EL LYOUSSI", cin: "CB19245", tel: "661084779", tpe: 0, espece: 4000, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "AV COACHING HAYAT" },
        { contrat: "14231", commercial: "SARAH", nom: "RAYANE BOUSFIHA", cin: "", tel: "656611959", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS" },
        { contrat: "12814", commercial: "REDA", nom: "IMAD BENKIRANE", cin: "", tel: "663597237", tpe: 0, espece: 1000, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COMP COACHING 10" },
        { contrat: "14233", commercial: "REDA", nom: "BOURAQBA SAMIR", cin: "CD530922", tel: "655917665", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS" },
        { contrat: "14234", commercial: "REDA", nom: "AIOUCHE MOHAMED", cin: "CD509340", tel: "677174133", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS" },
        { contrat: "14235", commercial: "-", nom: "EL GHAYOUR WIAM", cin: "CD480264", tel: "", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "OFFERT PAR LA DIRECTION" },
        { contrat: "14236", commercial: "-", nom: "THINE MOHAMED", cin: "CD206804", tel: "", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "OFFERT PAR LA DIRECTION" },
        { contrat: "14237", commercial: "-", nom: "ELM GHAYOUR OUSSAMA", cin: "CD243093", tel: "", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "OFFERT PAR LA DIRECTION" }
    ],
    "2026-04-10": [
        { contrat: "14238", commercial: "REDA", nom: "BENCHAKROUN HANAN", cin: "BJ70702", tel: "662063655", tpe: 0, espece: 0, virement: 0, cheque: 7300, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
        { contrat: "12619", commercial: "REDA", nom: "DALYLA EL LYOUSSI", cin: "CB19245", tel: "661084779", tpe: 0, espece: 2000, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "COMP COACHING HAYAT" },
        { contrat: "13818", commercial: "AHLAM", nom: "RHEMOUL SAFAE", cin: "CD243008", tel: "616857877", tpe: 1000, espece: 1000, virement: 0, cheque: 3250, abonnement: "1 AN", note_reste: "12 mois" },
        { contrat: "14239", commercial: "AHLAM", nom: "OUHBI FATIMAZAHRA", cin: "-18", tel: "766613782", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
        { contrat: "14240", commercial: "REDA", nom: "SEDATI IMANE", cin: "CD915645", tel: "646441429", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
        { contrat: "", commercial: "SABER", nom: "AMIR CHABAT", cin: "", tel: "662088003", tpe: 200, espece: 0, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "ACCES JOURNALIER" }
    ],
    "2026-04-12": [
        { contrat: "14241", commercial: "SABER", nom: "BAKI ABDESLAM", cin: "UC60605", tel: "664150150", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
        { contrat: "14242", commercial: "REDA", nom: "FILALI SADOUK AMINE", cin: "CD486817", tel: "", tpe: 0, espece: 0, virement: 0, cheque: 5900, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" },
        { contrat: "14243", commercial: "REDA", nom: "HAJJI LAILA", cin: "C387659", tel: "353877763364", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "AUTRE", note_reste: "PROMO SAINT VALENTIN" }
    ]
};

async function run() {
    console.log("🚀 Starting Bulk Import...");
    
    for (const [dateStr, entries] of Object.entries(dataByDay)) {
        console.log(`\n📅 Processing ${dateStr}...`);
        const docId = `${gymId}_${dateStr}`;
        
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
    }
    
    console.log("\n✨ Bulk Import Complete!");
    process.exit(0);
}

run().catch(err => {
    console.error("❌ Fatal error:", err);
    process.exit(1);
});
