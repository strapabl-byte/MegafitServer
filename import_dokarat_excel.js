const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

// Initialize Firebase Admin
const saPath = path.join(__dirname, "serviceAccount.json");
if (!fs.existsSync(saPath)) {
  console.error("❌ serviceAccount.json not found in", saPath);
  process.exit(1);
}
const serviceAccount = require(saPath);

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

const gymId = "dokarat";

const allData = {
  "2026-04-01": [
    { contrat: "14108", commercial: "OUISSALE", nom: "SARA NHAILA", cin: "-", tel: "0666505074", tpe: 2200, espece: 0, virement: 0, cheque: 0, abonnement: "3 MOIS" },
    { contrat: "14114", commercial: "OUISSALE", nom: "IBTISSAM TAIDI", cin: "KB187333", tel: "0682059502", tpe: 6300, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14113", commercial: "OUISSALE", nom: "NISRINE AZMAMI", cin: "CD590260", tel: "0666724766", tpe: 3000, espece: 1000, virement: 0, cheque: 0, abonnement: "1 AN" },
    { contrat: "14111", commercial: "OUISSALE", nom: "LIKRAM ISRAA", cin: "BB213740", tel: "0715361523", tpe: 6300, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14110", commercial: "HAJARE", nom: "ALAMI LAMYAE", cin: "K455429", tel: "0662677071", tpe: 0, espece: 0, virement: 0, cheque: 1500, abonnement: "CONV. CREDIT AGRICOLE 1 AN" },
    { contrat: "14112", commercial: "HAJARE", nom: "KARIM ZOUINE", cin: "C390320", tel: "0666512415", tpe: 0, espece: 800, virement: 0, cheque: 700, abonnement: "CONV. CREDIT AGRICOLE 1 AN" },
    { contrat: "14109", commercial: "HAJARE", nom: "KAMARE ZINEB", cin: "DAI15695", tel: "0663188402", tpe: 0, espece: 0, virement: 6000, cheque: 0, abonnement: "KIDS 2 ANS" },
    { contrat: "14116", commercial: "HAJARE", nom: "KHALID BAALI", cin: "UB50980", tel: "0661300674", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14115", commercial: "HAJARE", nom: "WISSAL KOUDIA", cin: "AD167409", tel: "0620151937", tpe: 2000, espece: 0, virement: 0, cheque: 3900, abonnement: "2 ANS S/V" }
  ],
  "2026-04-02": [
    { contrat: "14117", commercial: "OUISSALE", nom: "OUAFAE LAKHOUSLI M.", cin: "C358796", tel: "0610058034", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14119", commercial: "HAJARE", nom: "MACHROUH DRISS", cin: "C377127", tel: "0645287176", tpe: 0, espece: 2000, virement: 0, cheque: 3900, abonnement: "2 ANS S/V" },
    { contrat: "14118", commercial: "OUISSALE", nom: "ESHIMI WIDAD", cin: "DB29244", tel: "0634844768", tpe: 1900, espece: 4000, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14121", commercial: "OUISSALE", nom: "TOURIYA NOURI", cin: "C374639", tel: "0663178633", tpe: 0, espece: 4000, virement: 0, cheque: 0, abonnement: "1 AN" },
    { contrat: "14122", commercial: "OUISSALE", nom: "NAJOUA LAABID", cin: "CD460404", tel: "0663178633", tpe: 0, espece: 4000, virement: 0, cheque: 0, abonnement: "1 AN" },
    { contrat: "14123", commercial: "OUISSALE", nom: "AHMED RAHIOUI", cin: "UC53905", tel: "0630738080", tpe: 6300, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14120", commercial: "HAJARE", nom: "ALKIR SOUAD", cin: "R307519", tel: "0629661054", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "13509", commercial: "HAJARE", nom: "AZZOUI FATIMA ZEHRA", cin: "-", tel: "-", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "13508", commercial: "HAJARE", nom: "AZZIOUI ABDELMAJID", cin: "-", tel: "-", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "13507", commercial: "HAJARE", nom: "TOUAB ABDERHAHIM", cin: "-", tel: "-", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS S/V" }
  ],
  "2026-04-03": [
    { contrat: "14124", commercial: "OUISSALE", nom: "ZOLIKHA HADDACHE", cin: "Z2680", tel: "0641525976", tpe: 3000, espece: 0, virement: 0, cheque: 0, abonnement: "AV DE 2 ANS" },
    { contrat: "14125", commercial: "OUISSALE", nom: "CHAHD MSA", cin: "CD416932", tel: "0650845382", tpe: 0, espece: 3000, virement: 0, cheque: 0, abonnement: "AV DE 2 ANS" },
    { contrat: "14126", commercial: "HAJARE", nom: "EL BARAKA NAJOUA", cin: "CD719910", tel: "0666527869", tpe: 0, espece: 4000, virement: 0, cheque: 0, abonnement: "1 AN" },
    { contrat: "PDC", commercial: "HAJARE", nom: "MRABET YASMINE", cin: "-", tel: "-", tpe: 0, espece: 0, virement: 0, cheque: 1000, abonnement: "-" },
    { contrat: "14128", commercial: "OUISSALE", nom: "ALAOUI ABDELAH I.", cin: "-", tel: "0661720873", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14127", commercial: "OUISSALE", nom: "KENZA AMLLAL", cin: "CD310898", tel: "0661692940", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14129", commercial: "HAJARE", nom: "ALI EL FARSI", cin: "C407397", tel: "0663785379", tpe: 0, espece: 0, virement: 4000, cheque: 0, abonnement: "1 AN" },
    { contrat: "141230", commercial: "OUISSALE", nom: "ACHRAF IBNILMAJDOUL", cin: "-", tel: "0664902713", tpe: 0, espece: 4000, virement: 0, cheque: 0, abonnement: "1 AN" },
    { contrat: "14132", commercial: "HAJARE", nom: "GHITA WARRACH", cin: "CD87099", tel: "0660740436", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14131", commercial: "HAJARE", nom: "ALI AIT OU LAHYANE", cin: "C967004", tel: "0666594874", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14133", commercial: "HAJARE", nom: "YOUNES OULAHYANE", cin: "-", tel: "0606717266", tpe: 0, espece: 0, virement: 2900, cheque: 0, abonnement: "AV DE 2 ANS" }
  ],
  "2026-04-04": [
    { contrat: "14136", commercial: "OUISSALE", nom: "BELCHHEB CHAFIK", cin: "D655521", tel: "0660238159", tpe: 0, espece: 1000, virement: 0, cheque: 0, abonnement: "TRANSFERT 1 AN" },
    { contrat: "14123", commercial: "MR MEHDI", nom: "ISMAILI KARIM", cin: "C384051", tel: "0671523767", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "1 AN OFFERT" },
    { contrat: "14138", commercial: "OUISSALE", nom: "KOTBA YAHYA", cin: "KIDS", tel: "0663602936", tpe: 0, espece: 3750, virement: 0, cheque: 0, abonnement: "KIDS 1 AN" },
    { contrat: "14135", commercial: "OUISSALE", nom: "EL-BAKKOURI M.", cin: "C4775", tel: "0678657488", tpe: 0, espece: 2900, virement: 0, cheque: 3000, abonnement: "2 ANS S/V" },
    { contrat: "14137", commercial: "HAJARE", nom: "BESALIHASSANI MANAL", cin: "CD318409", tel: "0658881944", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14134", commercial: "HAJARE", nom: "ABDELLOUI SARAH", cin: "T178268", tel: "0628254874", tpe: 3000, espece: 0, virement: 0, cheque: 2900, abonnement: "2 ANS S/V" },
    { contrat: "14141", commercial: "OUISSALE", nom: "TAHBOUCH SOUKAINA", cin: "CD599946", tel: "0697479424", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14140", commercial: "OUISSALE", nom: "YU-CHEN LIU", cin: "C026150R", tel: "0664598222", tpe: 0, espece: 3600, virement: 0, cheque: 0, abonnement: "CARNER D'ENTRER" },
    { contrat: "14142", commercial: "HAJARE", nom: "YONNES SOUD", cin: "CD284921", tel: "0661375699", tpe: 0, espece: 800, virement: 0, cheque: 0, abonnement: "TRANSFERT" },
    { contrat: "14143", commercial: "HAJARE", nom: "BENNANN MOHAMED", cin: "BI334829", tel: "0663102612", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14144", commercial: "OUISSALE", nom: "ABDELAZIZ EL BAHYAOUI", cin: "CD505498", tel: "0635554980", tpe: 3000, espece: 0, virement: 0, cheque: 0, abonnement: "AV 2 ANS S/V" },
    { contrat: "14125", commercial: "OUISSALE", nom: "CHAHD HSAKEN", cin: "CD416932", tel: "0650845382", tpe: 0, espece: 2900, virement: 0, cheque: 0, abonnement: "COMPL. 2 ANS S/V" }
  ],
  "2026-04-05": [
    { contrat: "14145", commercial: "OUISSALE", nom: "hasmoudi hassaniya", cin: "fs82589", tel: "0772343517", tpe: 3000, espece: 0, virement: 0, cheque: 0, abonnement: "AV DE 2 ANS S/V" },
    { contrat: "14146", commercial: "HAJARE", nom: "imane bourissai", cin: "cd175425", tel: "0617900010", tpe: 0, espece: 0, virement: 1500, cheque: 0, abonnement: "CONV. CREDIT AGRICOLE" }
  ],
  "2026-04-06": [
    { contrat: "-", commercial: "OUISSALE", nom: "BOUCHRA BOUAYACH", cin: "-", tel: "-", tpe: 0, espece: 400, virement: 0, cheque: 0, abonnement: "2 TICKETS ENTRÉE" },
    { contrat: "14147", commercial: "HAJARE", nom: "mohammed bouabdalli", cin: "AB257598", tel: "-", tpe: 0, espece: 1500, virement: 0, cheque: 0, abonnement: "CONVENTION" },
    { contrat: "14148", commercial: "OUISSALE", nom: "AMAL EZZARZOUR", cin: "CD556067", tel: "0660646501", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "-", commercial: "OUISSALE", nom: "MOHAMED MOUNTASSER", cin: "PZ810229", tel: "-", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "1 TICKET ENTRÉE" },
    { contrat: "14149", commercial: "HAJARE", nom: "FATIMAZAHRA B.", cin: "CD82330", tel: "0657382107", tpe: 400, espece: 5500, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "-", commercial: "HAJARE", nom: "REDA JABER", cin: "CD221864", tel: "0652760838", tpe: 0, espece: 400, virement: 0, cheque: 0, abonnement: "AV DE MULTICUB" }
  ],
  "2026-04-07": [
    { contrat: "14150", commercial: "OUISSALE", nom: "EL AOUALE OUAFAE", cin: "C444315", tel: "0645351284", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14152", commercial: "HAJARE", nom: "OMAR BEN JELLOUN F.", cin: "CD650383", tel: "0664955144", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14153", commercial: "HAJARE", nom: "MOHAMED BAKKALI", cin: "CD591135", tel: "0661165511", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14154", commercial: "OUISSALE", nom: "FASSI FIHRI BADIA", cin: "C367746", tel: "0663806032", tpe: 6900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14155", commercial: "OUISSALE", nom: "FATIHA EL-HAJJOUI", cin: "C512094", tel: "0615401890", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14156", commercial: "HAJARE", nom: "BENNIS MOHAMMED", cin: "C909009", tel: "0620202095", tpe: 0, espece: 0, virement: 0, cheque: 1500, abonnement: "CONV. CREDIT AGRICOLE" },
    { contrat: "14157", commercial: "OUISSALE", nom: "SIMOHAMED NEJAR", cin: "-", tel: "0662031505", tpe: 0, espece: 0, virement: 6900, cheque: 0, abonnement: "2 ANS S/V" }
  ],
  "2026-04-08": [
    { contrat: "14162", commercial: "OUISSALE", nom: "RACHID ARROUB", cin: "C766625", tel: "0645262205", tpe: 0, espece: 6300, virement: 0, cheque: 0, abonnement: "2 ANS S/V (TRANSF)" },
    { contrat: "14158", commercial: "HAJARE", nom: "BADRI NAJIBA", cin: "C789058", tel: "0661525595", tpe: 0, espece: 0, virement: 5900, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14159", commercial: "MR MEHDI", nom: "HIND BADRI", cin: "CB250766", tel: "0666981879", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "1 AN OFFERT" },
    { contrat: "14161", commercial: "OFFERT", nom: "YASSINE LAFOUTAH", cin: "CD192655", tel: "0633202816", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "1 AN OFFERT" },
    { contrat: "14164", commercial: "MR TAZI", nom: "ISMAIL OUDGHIRI", cin: "CD129868", tel: "0617068937", tpe: 0, espece: 0, virement: 0, cheque: 0, abonnement: "1 AN OFFERT" },
    { contrat: "14160", commercial: "HAJARE", nom: "MAJIT NADIA", cin: "CD716209", tel: "0660912885", tpe: 1750, espece: 1700, virement: 0, cheque: 3450, abonnement: "2 ANS" },
    { contrat: "14163", commercial: "HAJARE", nom: "MERIEM LOUIZ", cin: "C435821", tel: "0611060633", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "2181-2200", commercial: "HAJARE", nom: "MOUAAD ROCHI I.", cin: "CD125844", tel: "0682373997", tpe: 0, espece: 0, virement: 0, cheque: 3600, abonnement: "COACHING (20 TICKETS)" },
    { contrat: "10762", commercial: "HAJARE", nom: "REDA JABER", cin: "CD221864", tel: "0652760838", tpe: 0, espece: 400, virement: 0, cheque: 0, abonnement: "COMP. MULTICLUB" }
  ],
  "2026-04-09": [
    { contrat: "14124", commercial: "OUISSALE", nom: "ZOLIKHA HADDACHE", cin: "Z2680", tel: "0641525976", tpe: 2900, espece: 0, virement: 0, cheque: 0, abonnement: "COMP. 2 ANS S/V" },
    { contrat: "14165", commercial: "ZINEB", nom: "SAID NACHIT", cin: "CD263708", tel: "0648526121", tpe: 600, espece: 5300, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14166", commercial: "HAJARE", nom: "SERHANE RAJAE", cin: "CD341500", tel: "0770398063", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14167", commercial: "OUISSALE", nom: "ABDELLAH EL ADDIDI", cin: "CD313254", tel: "0658942369", tpe: 0, espece: 5900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "206", commercial: "HAJARE", nom: "MEJDOUBI BAHAEDDIN", cin: "K505913", tel: "0664055754", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "ENTRÉE JOURNALIÈRE" },
    { contrat: "14170", commercial: "OUISSALE", nom: "ABDERRAMMANE E.", cin: "C513260", tel: "0674025979", tpe: 4000, espece: 1900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14169", commercial: "OUISSALE", nom: "HEMZA EL FOUNASSI", cin: "CD350288", tel: "0606605750", tpe: 4500, espece: 1400, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14168", commercial: "HAJARE", nom: "ALI BOUDINE", cin: "D943156", tel: "0661305451", tpe: 0, espece: 6300, virement: 0, cheque: 0, abonnement: "2 ANS S/V" }
  ],
  "2026-04-10": [
    { contrat: "14174", commercial: "OUISSALE", nom: "JAOUAD EL ABDALI", cin: "C609691", tel: "0665717707", tpe: 3900, espece: 2000, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14171", commercial: "HAJARE", nom: "HAKIMA AGBI", cin: "C419876", tel: "0662474891", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14172", commercial: "HAJARE", nom: "AICHA MABROUKI", cin: "KIDS", tel: "0662474891", tpe: 3500, espece: 0, virement: 0, cheque: 0, abonnement: "1 AN PACK FAM." },
    { contrat: "14173", commercial: "HAJARE", nom: "KARIMA MABROUKI", cin: "KIDS", tel: "0662474891", tpe: 1500, espece: 2000, virement: 0, cheque: 0, abonnement: "1 AN PACK FAM." },
    { contrat: "14175", commercial: "OUISSALE", nom: "SAIDI AMMINE", cin: "-", tel: "0691924667", tpe: 0, espece: 6900, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "207", commercial: "HAJARE", nom: "DOUHA ELAZIZI", cin: "CD795811", tel: "0775256600", tpe: 0, espece: 200, virement: 0, cheque: 0, abonnement: "ENTRÉE JOURN." },
    { contrat: "3001-3050", commercial: "HAJARE", nom: "ZOHRA & BOUTAINA", cin: "CD301432", tel: "0771925466", tpe: 0, espece: 3500, virement: 0, cheque: 0, abonnement: "COACHING (50S)" },
    { contrat: "14176", commercial: "OUISSALE", nom: "ISSAM HAYZOUN", cin: "CD470529", tel: "0679567221", tpe: 5900, espece: 0, virement: 0, cheque: 0, abonnement: "2 ANS S/V" },
    { contrat: "14177", commercial: "HAJARE", nom: "AMIN ZAIR", cin: "-", tel: "0644589114", tpe: 0, espece: 2250, virement: 0, cheque: 3000, abonnement: "1 AN" }
  ]
};

async function importData() {
  console.log(`🚀 Starting Dokarat register import for ${Object.keys(allData).length} days...`);
  
  for (const [date, entries] of Object.entries(allData)) {
    const docId = `${gymId}_${date}`;
    console.log(`\n📅 Processing ${date} (${entries.length} entries) -> ${docId}`);
    
    // 1. Ensure the parent document exists
    await db.collection("megafit_daily_register").doc(docId).set({
      gymId,
      date,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      source: "bulk_import_excel"
    }, { merge: true });

    // 2. Clear existing entries for this day to avoid duplicates if re-run
    const entriesRef = db.collection("megafit_daily_register").doc(docId).collection("entries");
    const existingEntries = await entriesRef.get();
    if (!existingEntries.empty) {
      console.log(`🧹 Clearing ${existingEntries.size} existing entries...`);
      const batch = db.batch();
      existingEntries.docs.forEach(doc => batch.delete(doc.ref));
      await batch.commit();
    }

    // 3. Add current entries
    const batch = db.batch();
    entries.forEach((entry, i) => {
      const entryData = {
        ...entry,
        prix: (entry.tpe || 0) + (entry.espece || 0) + (entry.virement || 0) + (entry.cheque || 0),
        source: "import_excel",
        createdAt: admin.firestore.Timestamp.fromDate(new Date(`${date}T10:00:00`)),
        createdBy: "SYSTEM_IMPORT"
      };
      
      const entryDocRef = entriesRef.doc();
      batch.set(entryDocRef, entryData);
    });
    
    await batch.commit();
    console.log(`✅ ${entries.length} entries imported for ${date}.`);
  }

  console.log("\n🎉 ALL DATA HAS BEEN REPLACED SUCCESSFULLY.");
  process.exit(0);
}

importData().catch(err => {
  console.error("❌ Fatal Error:", err);
  process.exit(1);
});
