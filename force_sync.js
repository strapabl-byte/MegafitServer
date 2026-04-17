
const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

// Load backend logic
const { syncGymCounts } = require('./auto_sync');
const lc = require('./localCache');

// Initialize Firebase
const saPath = path.join(__dirname, "serviceAccount.json");
const serviceAccount = JSON.parse(fs.readFileSync(saPath, 'utf8'));

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function runFix() {
  console.log("🛠️ Starting data repair for the last 3 days...");
  
  // We pass an empty object for apiCache to avoid side effects on the running server,
  // but it will still update SQLite and Firestore.
  const mockCache = { dailyStats: {} };
  
  // daysBack = 3 to cover 16th, 15th, 14th, 13th
  await syncGymCounts(db, mockCache, 3);
  
  console.log("\n✅ Data repair complete.");
  console.log("Verifying April 15 for dokarat in SQLite...");
  const stat = lc.getDailyStat('dokarat', '2026-04-15');
  console.log("Stat:", JSON.stringify(stat, null, 2));
  
  process.exit(0);
}

runFix().catch(err => {
  console.error("❌ Fix failed:", err);
  process.exit(1);
});
