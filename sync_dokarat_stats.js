const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

const saPath = path.join(__dirname, "serviceAccount.json");
const serviceAccount = require(saPath);

if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const gymId = "dokarat";
const realDates = [
  "2026-04-01", "2026-04-02", "2026-04-03", "2026-04-04", "2026-04-05",
  "2026-04-06", "2026-04-07", "2026-04-08", "2026-04-09", "2026-04-10"
];

async function cleanupAndSync() {
  console.log(`🧹 Cleaning up simulation data for ${gymId}...`);

  // 1. Clean up megafit_daily_register
  const registerSnap = await db.collection("megafit_daily_register")
    .where("gymId", "==", gymId)
    .get();

  console.log(`🔍 Found ${registerSnap.size} days in Register for ${gymId}.`);
  for (const doc of registerSnap.docs) {
    const data = doc.data();
    if (!realDates.includes(data.date)) {
      console.log(`🗑️ Deleting simulated Register day: ${data.date}`);
      
      // Delete entries sub-collection first
      const entriesSnap = await doc.ref.collection("entries").get();
      if (!entriesSnap.empty) {
        const batch = db.batch();
        entriesSnap.docs.forEach(e => batch.delete(e.ref));
        await batch.commit();
      }
      await doc.ref.delete();
    }
  }

  // 2. Clean up gym_daily_stats
  const statsSnap = await db.collection("gym_daily_stats")
    .where("gym_id", "==", gymId)
    .get();

  console.log(`🔍 Found ${statsSnap.size} days in Daily Stats for ${gymId}.`);
  for (const doc of statsSnap.docs) {
    const data = doc.data();
    if (!realDates.includes(data.date)) {
      console.log(`🗑️ Deleting simulated Stats day: ${data.date}`);
      await doc.ref.delete();
    }
  }

  // 3. Sync Real Data to gym_daily_stats
  console.log(`\n🔄 Syncing real stats for April 1-10...`);
  for (const date of realDates) {
    const docId = `${gymId}_${date}`;
    const entriesSnap = await db.collection("megafit_daily_register")
      .doc(docId)
      .collection("entries")
      .get();

    let totalIncome = 0;
    entriesSnap.docs.forEach(doc => {
      const d = doc.data();
      totalIncome += (d.tpe || 0) + (d.espece || 0) + (d.virement || 0) + (d.cheque || 0);
    });

    const count = entriesSnap.size;

    console.log(`📈 ${date}: ${count} registrations | CA: ${totalIncome.toLocaleString()} DH`);

    await db.collection("gym_daily_stats").doc(docId).set({
      gym_id: gymId,
      date: date,
      count: count,           // Using registration count as check-in base for these real days
      rawCount: count,
      income: totalIncome,    // Storing income here for future dashboard features
      lastSyncedAt: admin.firestore.FieldValue.serverTimestamp(),
      source: "real_import"
    }, { merge: true });
  }

  console.log("\n✨ Cleanup and Sync complete!");
  process.exit(0);
}

cleanupAndSync().catch(console.error);
