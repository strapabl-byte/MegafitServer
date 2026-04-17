
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

async function checkLatest(collectionName, locationTags, dateStr) {
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;
  
  const body = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: {
        fieldFilter: {
          field: { fieldPath: "timestamp" },
          op: "GREATER_THAN_OR_EQUAL",
          value: { stringValue: dateStr }
        }
      },
      orderBy: [{ field: { fieldPath: "timestamp" }, direction: "DESCENDING" }],
      limit: 10
    }
  };

  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  const docs = Array.isArray(data) ? data.filter(item => item.document).map(item => item.document) : [];
  
  console.log(`\n🕒 Last 10 logs for ${collectionName} since ${dateStr}:`);
  docs.forEach(d => {
    const f = d.fields;
    console.log(`  - [${f.timestamp?.stringValue}] Location: ${f.location?.stringValue}, User: ${f.user_id?.stringValue || '?'}`);
  });
}

const today = "2026-04-16";
checkLatest("mega_fit_logs", ["dokkarat fes"], today).catch(console.error);
