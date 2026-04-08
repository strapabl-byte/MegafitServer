// sync_historical_30d.js
// FETCHES RAW LOGS FOR THE LAST 30 DAYS AND SAVES AGGREGATED TOTALS

const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const serverDb = admin.firestore();

const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

async function fetchFromDoor(collectionName) {
    let allDocs = [];
    let pageToken = "";
    do {
        const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents/${collectionName}?pageSize=300${pageToken ? `&pageToken=${pageToken}` : ""}&key=${DOOR_API_KEY}`;
        const response = await fetch(url);
        const data = await response.json();
        if (data.documents) allDocs = allDocs.concat(data.documents);
        pageToken = data.nextPageToken || "";
    } while (pageToken);
    return allDocs;
}

// 🛡️ Deduplication Helper (10m window) — returns { unique, raw }
function getDeduplicatedCount(docs, dateStr, locationTag) {
    const filtered = docs.filter(doc => {
        const f = doc.fields || {};
        const timestamp = f.timestamp?.stringValue || "";
        const loc = f.location?.stringValue || "";
        return timestamp.startsWith(dateStr) && loc === locationTag;
    });

    const raw = filtered.length;

    const sorted = [...filtered].sort((a,b) => 
        (a.fields.timestamp?.stringValue || "").localeCompare(b.fields.timestamp?.stringValue || "")
    );

    const visitorLastSeen = new Map();
    let unique = 0;

    sorted.forEach(doc => {
        const f = doc.fields;
        const uid = f.user_id?.stringValue || f.id?.stringValue || doc.name.split("/").pop();
        const time = new Date(f.timestamp.stringValue).getTime();
        
        if (!visitorLastSeen.has(uid) || (time - visitorLastSeen.get(uid) >= 600000)) {
            unique++;
            visitorLastSeen.set(uid, time);
        }
    });

    return { unique, raw };
}

async function syncAll() {
    console.log("🕒 Starting 30-day Historical Sync...");
    
    // Fetch ALL logs once to avoid excessive API calls
    console.log("📊 Fetching all Dokarat logs...");
    const dokaratDocs = await fetchFromDoor('mega_fit_logs');
    console.log("📊 Fetching all Saiss logs...");
    const saissDocs = await fetchFromDoor('saiss entrees logs');

    const gyms = [
        { id: 'dokarat', docs: dokaratDocs, location: 'dokkarat fes' },
        { id: 'marjane', docs: saissDocs, location: 'fes saiss' }
    ];

    const today = new Date();
    for (let i = 29; i >= 0; i--) {
        const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i);
        const dateStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
        
        console.log(`📡 Processing: ${dateStr}...`);
        
        for (const gym of gyms) {
            const { unique, raw } = getDeduplicatedCount(gym.docs, dateStr, gym.location);
            const docId = `${gym.id}_${dateStr}`;
            
            await serverDb.collection("gym_daily_stats").doc(docId).set({
                gym_id: gym.id,
                date: dateStr,
                count: unique,
                rawCount: raw,
                lastSyncedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            
            console.log(`   ✅ ${gym.id}: ${unique} unique (${raw} bruts).`);
        }
    }

    console.log("\n✨ Historical Sync Complete! The 30-day chart is now powered by real data.");
    process.exit(0);
}

syncAll().catch(e => {
    console.error("❌ Sync Failed:", e);
    process.exit(1);
});
