// dokarat_last3days.js — Raw deduplicated entry count for last 3 days at Dokkarat

const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";
const LOCATION_TAG = "dokkarat fes";
const COLLECTION = "mega_fit_logs";

// Build last 3 day strings in Morocco time (UTC+1)
function getMoroccanDateStr(daysAgo = 0) {
    const d = new Date();
    d.setTime(d.getTime() + (60 * 60 * 1000)); // UTC+1
    d.setUTCDate(d.getUTCDate() - daysAgo);
    return d.toISOString().slice(0, 10);
}

async function fetchAll() {
    let all = [];
    let pageToken = "";
    do {
        const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents/${COLLECTION}?pageSize=300${pageToken ? `&pageToken=${pageToken}` : ""}&key=${DOOR_API_KEY}`;
        const res = await fetch(url);
        const data = await res.json();
        if (data.documents) all = all.concat(data.documents);
        pageToken = data.nextPageToken || "";
    } while (pageToken);
    return all;
}

function getDeduplicatedCount(docs, dateStr) {
    const filtered = docs.filter(doc => {
        const f = doc.fields || {};
        const timestamp = f.timestamp?.stringValue || "";
        const loc = f.location?.stringValue || "";
        return timestamp.startsWith(dateStr) && loc === LOCATION_TAG;
    });

    const sorted = [...filtered].sort((a, b) =>
        (a.fields.timestamp?.stringValue || "").localeCompare(b.fields.timestamp?.stringValue || "")
    );

    const visitorLastSeen = new Map();
    let count = 0;
    let raw = 0;

    sorted.forEach(doc => {
        const f = doc.fields;
        const uid = f.user_id?.stringValue || doc.name.split("/").pop();
        const time = new Date(f.timestamp.stringValue).getTime();
        raw++;
        if (!visitorLastSeen.has(uid) || (time - visitorLastSeen.get(uid)) >= 600000) {
            count++;
            visitorLastSeen.set(uid, time);
        }
    });

    return { raw, unique: count };
}

async function run() {
    console.log("📡 Fetching Dokkarat logs...\n");
    const allDocs = await fetchAll();
    console.log(`📦 Total docs fetched: ${allDocs.length}`);

    const dates = ["2026-04-02", getMoroccanDateStr(2), getMoroccanDateStr(1), getMoroccanDateStr(0)];
    let grandTotal = 0;

    console.log("\n" + "═".repeat(50));
    console.log("  📊  DOKKARAT — LAST 3 DAYS");
    console.log("═".repeat(50));

    dates.forEach(dateStr => {
        const { raw, unique } = getDeduplicatedCount(allDocs, dateStr);
        grandTotal += unique;
        console.log(`  📅 ${dateStr}:  ${unique} entrées uniques  (${raw} scans bruts)`);
    });

    console.log("═".repeat(50));
    console.log(`  🏆 TOTAL 3 JOURS:  ${grandTotal} entrées uniques`);
    console.log("═".repeat(50));
}

run().catch(console.error);
