const admin = require("firebase-admin");
const { syncGymCounts } = require("../auto_sync");

// Initialize Firebase Admin (using local serviceAccount.json)
const serviceAccount = require("../serviceAccount.json");
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const db = admin.firestore();

// No API cache needed for manual sync script
const apiCache = {};

async function run() {
    console.log("🚀 Starting manual historical sync with updated multi-tag logic...");
    // Sync last 7 days to cover April 9-12
    await syncGymCounts(db, apiCache, 7);
    console.log("✨ Manual sync complete!");
    process.exit(0);
}

run().catch(err => {
    console.error("❌ Sync failed:", err);
    process.exit(1);
});
