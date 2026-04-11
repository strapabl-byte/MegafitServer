const admin = require("firebase-admin");
const path = require("path");

const saPath = path.join(__dirname, "serviceAccount.json");
const serviceAccount = require(saPath);

if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const gymId = "dokarat";

async function fixNames() {
  console.log(`🔍 Searching for entries with commercial 'HAJAR' in ${gymId}...`);

  // We need to iterate through all day documents for the gym
  const registerSnap = await db.collection("megafit_daily_register")
    .where("gymId", "==", gymId)
    .get();

  let totalUpdated = 0;

  for (const dayDoc of registerSnap.docs) {
    const entriesRef = dayDoc.ref.collection("entries");
    
    // Find entries where commercial is "HAJAR" (case-insensitive search isn't native, so we fetch and filter)
    const entriesSnap = await entriesRef.get();
    
    const batch = db.batch();
    let batchSize = 0;

    entriesSnap.docs.forEach(doc => {
      const data = doc.data();
      const name = (data.commercial || "").trim().toUpperCase();
      
      if (name === "HAJAR") {
        console.log(`  📝 Updating entry ${doc.id} on ${dayDoc.id}: ${data.nom} | ${data.commercial} -> HAJARE`);
        batch.update(doc.ref, { commercial: "HAJARE" });
        batchSize++;
        totalUpdated++;
      }
    });

    if (batchSize > 0) {
      await batch.commit();
      console.log(`  ✅ Committed batch of ${batchSize} updates for ${dayDoc.id}`);
    }
  }

  console.log(`\n✨ Finished! Total entries updated: ${totalUpdated}`);
  process.exit(0);
}

fixNames().catch(console.error);
