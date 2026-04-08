// fetch_last_dokarat.js
// Fetches the most recent entries from the Dokkarat location (mega_fit_logs)

const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";
const LOCATION_TAG = "dokkarat fes";
const COLLECTION = "mega_fit_logs";
const LIMIT = 20; // How many last entries to show

async function fetchAll(collectionName) {
    let all = [];
    let pageToken = "";
    do {
        const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents/${collectionName}?pageSize=300${pageToken ? `&pageToken=${pageToken}` : ""}&key=${DOOR_API_KEY}`;
        const res = await fetch(url);
        const data = await res.json();
        if (data.documents) all = all.concat(data.documents);
        pageToken = data.nextPageToken || "";
    } while (pageToken);
    return all;
}

async function run() {
    console.log(`🔍 Fetching last entries from Dokkarat (${COLLECTION})...`);

    const allDocs = await fetchAll(COLLECTION);
    console.log(`📦 Total docs in collection: ${allDocs.length}`);

    const dokaratDocs = allDocs
        .filter(d => {
            const f = d.fields || {};
            return f.location?.stringValue === LOCATION_TAG;
        })
        .map(d => ({
            docId: d.name.split("/").pop(),
            id: d.fields.user_id?.stringValue || d.fields.id?.stringValue || "N/A",
            name: d.fields.name?.stringValue || "N/A",
            time: d.fields.timestamp?.stringValue || "N/A",
            location: d.fields.location?.stringValue || "N/A",
        }))
        .sort((a, b) => b.time.localeCompare(a.time)); // newest first

    const last = dokaratDocs.slice(0, LIMIT);

    console.log(`\n✅ Found ${dokaratDocs.length} total Dokkarat entries.`);
    console.log(`📋 Showing last ${last.length}:\n`);
    console.log("─".repeat(70));

    last.forEach((e, i) => {
        console.log(`[${String(i + 1).padStart(2, "0")}] 🕐 ${e.time.replace("T", " ").slice(0, 19)}`);
        console.log(`      👤 ${e.name} (ID: ${e.id})`);
        console.log(`      📍 ${e.location} | Doc: ${e.docId}`);
        console.log("─".repeat(70));
    });

    if (last.length > 0) {
        console.log(`\n🏆 Most recent entry: ${last[0].name} at ${last[0].time.replace("T", " ").slice(0, 19)}`);
    }
}

run().catch(console.error);
