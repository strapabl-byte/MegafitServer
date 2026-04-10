const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

const saPath = path.join(__dirname, "serviceAccount.json");
const serviceAccount = require(saPath);

if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

async function verify() {
  const dates = [
    "2026-04-01", "2026-04-02", "2026-04-03", "2026-04-04", "2026-04-05",
    "2026-04-06", "2026-04-07", "2026-04-08", "2026-04-09", "2026-04-10"
  ];
  
  console.log("🧪 Verification of Dokarat imported data:");
  
  for (const date of dates) {
    const snap = await db.collection("megafit_daily_register").doc(`dokarat_${date}`).collection("entries").get();
    console.log(`✅ ${date}: ${snap.size} entries`);
  }
  
  // Sample check for April 1st
  const firstEntry = await db.collection("megafit_daily_register").doc("dokarat_2026-04-01").collection("entries").limit(1).get();
  if (!firstEntry.empty) {
    console.log("\n📄 Sample entry from 01/04:", firstEntry.docs[0].data().nom);
  }
  
  process.exit(0);
}

verify().catch(console.error);
