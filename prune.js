const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const DOC_ID = 'dokarat_2026-04-18';

// The DEFINITIVE 12 exact entries the user wants to KEEP.
const definitiveData = [
  { contrat: "14366", nom: "MERROUNI ISMAIL" },
  { contrat: "14368", nom: "RABIA BOUHAFS" },
  { contrat: "14367", nom: "AZIZ RAJAE" },
  { contrat: "14369", nom: "ABDELLAH OUBOUQSSI" },
  { contrat: "", nom: "HICHAM BENABDELHAFID" },
  { contrat: "14363", nom: "FATIMAZAHRA FARAES" },
  { contrat: "14370", nom: "NEZHA EL ARABI" },
  { contrat: "14352", nom: "BOULAGHMOUD MOSTAFA" },
  { contrat: "14371", nom: "BADAR ASMAR" },
  { contrat: "14372", nom: "ABDELHAK MAGHRANE" },
  { contrat: "14373", nom: "YASSER HILALI" },
  { contrat: "14374", nom: "YOUSSEF EL SHODDANI" }
];

async function prune() {
  const colRef = db.collection('megafit_daily_register').doc(DOC_ID).collection('entries');
  const snap = await colRef.get();
  
  console.log(`Initial count in Firestore: ${snap.size}`);

  let deletedCount = 0;
  
  for (const doc of snap.docs) {
    const d = doc.data();
    const docNom = String(d.nom).trim().toLowerCase();
    
    // Check if this document perfectly matches one of the definitive items!
    // We match by names (case insensitive) to know if we should keep it.
    const isKeeper = definitiveData.some(def => String(def.nom).trim().toLowerCase() === docNom);

    if (!isKeeper) {
      console.log(`🗑️ Deleting garbage entry: ${d.nom} (Contrat: ${d.contrat})`);
      await doc.ref.delete();
      deletedCount++;
    } else {
        // Even if it's a keeper, is it a duplicate?
        // Wait, what if there are two "Aziz Rajae"? 
        // We will keep BOTH if we just do `isKeeper`, so let's de-duplicate!
    }
  }
}

async function advancedPrune() {
    const colRef = db.collection('megafit_daily_register').doc(DOC_ID).collection('entries');
    const snap = await colRef.get();
    
    // Set up tracking to prevent duplicates of keepers
    const keepersFound = new Set();
    let deletedCount = 0;

    for (const doc of snap.docs) {
      const d = doc.data();
      const docNom = String(d.nom).trim().toLowerCase();
      
      const definitiveMatch = definitiveData.find(def => String(def.nom).trim().toLowerCase() === docNom);

      if (!definitiveMatch) {
          console.log(`🗑️ Deleting Non-List Entry: ${d.nom} (Contrat: ${d.contrat})`);
          await doc.ref.delete();
          deletedCount++;
      } else {
          // It's on the list! Have we seen it already?
          if (keepersFound.has(docNom)) {
              console.log(`🗑️ Deleting Duplicate: ${d.nom} (Contrat: ${d.contrat})`);
              await doc.ref.delete();
              deletedCount++;
          } else {
              // It's the first time seeing this keeper! We keep it.
              console.log(`✅ Keeping: ${d.nom}`);
              keepersFound.add(docNom);
              
              // Let's ALSO force-update its contract number to match the sheet exactly just in case!
              const correctContrat = definitiveMatch.contrat;
              if (String(d.contrat).trim() !== correctContrat) {
                  console.log(`   ✏️ Fixing contract number to ${correctContrat}`);
                  await doc.ref.update({ contrat: correctContrat });
              }
          }
      }
    }
    
    console.log(`\nPruning complete! Deleted ${deletedCount} records.`);
    
    // Hard Wipe SQLite cache for Dokarat so it's forced to re-fetch!
    const Database = require('better-sqlite3');
    const path = require('path');
    const DB_PATH = path.join(__dirname, 'megafit_cache.db');
    const sqlite = new Database(DB_PATH);
    sqlite.prepare("DELETE FROM register_cache WHERE gymId = 'dokarat' AND date = '2026-04-18'").run();
    sqlite.close();
    console.log("🧹 Wiped local SQLite cache for dokarat_2026-04-18 to force fresh pull on next request.");

    process.exit(0);
}

advancedPrune();
