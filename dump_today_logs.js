// dump_today_logs.js
// FETCHES RAW LOGS FOR TODAY TO ANALYZE DUPLICATES

const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";
const TODAY = "2026-04-02";

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
    console.log(`🔍 Dumping logs for ${TODAY}...`);
    
    // 1. Dokarat
    const dokaratDocs = await fetchAll("mega_fit_logs");
    const dokaratToday = dokaratDocs.filter(d => {
        const f = d.fields || {};
        return f.timestamp?.stringValue?.startsWith(TODAY) && f.location?.stringValue === "dokkarat fes";
    }).map(d => ({
        id: d.fields.user_id?.stringValue || d.fields.id?.stringValue || "N/A",
        name: d.fields.name?.stringValue || "N/A",
        time: d.fields.timestamp?.stringValue || "N/A"
    })).sort((a,b) => a.time.localeCompare(b.time));

    // 2. Fès Saiss
    const saissDocs = await fetchAll("saiss entrees logs");
    const saissToday = saissDocs.filter(d => {
        const f = d.fields || {};
        return f.timestamp?.stringValue?.startsWith(TODAY) && f.location?.stringValue === "fes saiss";
    }).map(d => ({
        id: d.fields.user_id?.stringValue || d.fields.id?.stringValue || "N/A",
        name: d.fields.name?.stringValue || "N/A",
        time: d.fields.timestamp?.stringValue || "N/A"
    })).sort((a,b) => a.time.localeCompare(b.time));

    const result = {
        date: TODAY,
        dokarat: { count: dokaratToday.length, logs: dokaratToday },
        saiss: { count: saissToday.length, logs: saissToday }
    };

    console.log(`✅ Collected ${dokaratToday.length} logs for Dokarat`);
    console.log(`✅ Collected ${saissToday.length} logs for Saiss`);

    require('fs').writeFileSync('today_raw_logs.json', JSON.stringify(result, null, 2));
    console.log("📂 Results saved to today_raw_logs.json");
}

run().catch(console.error);
