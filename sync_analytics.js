const admin = require("firebase-admin");

// 1. Initialize Server Project (mega-b891d) - Where we SAVE the stats
const serviceAccount = require("./serviceAccount.json");
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const serverDb = admin.firestore();

// 2. Door Project Details (megadoor-b3ccb) - Where we READ raw logs via REST
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

async function fetchFromDoor(collectionName) {
    let allDocs = [];
    let pageToken = "";
    
    do {
        const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents/${collectionName}?pageSize=300${pageToken ? `&pageToken=${pageToken}` : ""}&key=${DOOR_API_KEY}`;
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.documents) {
            allDocs = allDocs.concat(data.documents);
        }
        pageToken = data.nextPageToken || "";
    } while (pageToken);
    
    return allDocs;
}

async function syncToday() {
    const todayStr = "2026-04-02"; // April 2nd, 2026
    console.log(`🚀 Starting SECURE REST sync for: ${todayStr}`);

    const gyms = [
        { id: 'dokarat', collection: 'mega_fit_logs', location: 'dokkarat fes' },
        { id: 'marjane', collection: 'saiss entrees logs', location: 'fes saiss' }
    ];

    for (const gym of gyms) {
        console.log(`📊 Fetching counts for ${gym.id}...`);
        const docs = await fetchFromDoor(gym.collection);
        
        // Filter by date and location
        const filteredDocs = docs.filter(doc => {
            const fields = doc.fields || {};
            const timestamp = fields.timestamp?.stringValue || "";
            const location = fields.location?.stringValue || "";
            return timestamp.startsWith(todayStr) && location === gym.location;
        });

        // 🛡️ Implement 10-minute deduplication logic
        // Sort by timestamp first
        const sortedDocs = [...filteredDocs].sort((a,b) => 
            (a.fields?.timestamp?.stringValue || "").localeCompare(b.fields?.timestamp?.stringValue || "")
        );

        const visitorLastSeen = new Map();
        let deduplicatedCount = 0;

        sortedDocs.forEach(doc => {
            const f = doc.fields;
            const uid = f.user_id?.stringValue || f.id?.stringValue || doc.name.split("/").pop();
            const time = new Date(f.timestamp.stringValue).getTime();
            
            if (!visitorLastSeen.has(uid) || (time - visitorLastSeen.get(uid) >= 600000)) {
                deduplicatedCount++;
                visitorLastSeen.set(uid, time);
            }
        });

        console.log(`   Found ${filteredDocs.length} real logs, but ONLY ${deduplicatedCount} unique visits (10m window).`);

        // 3. SECURELY SAVE to Server project (mega-b891d)
        const docId = `${gym.id}_${todayStr}`;
        await serverDb.collection("gym_daily_stats").doc(docId).set({
            gym_id: gym.id,
            date: todayStr,
            count: deduplicatedCount,
            lastSyncedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        console.log(`   ✅ Summary for ${gym.id} saved in mega-b891d.`);
    }

    console.log("\n✨ Sync complete!");
    process.exit(0);
}

syncToday().catch(e => {
    console.error("❌ Aggregation failed:", e);
    process.exit(1);
});
