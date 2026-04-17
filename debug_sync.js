
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

async function testQuery(collectionName, dateStr) {
  const nextDay = new Date(new Date(dateStr).getTime() + 86400000).toISOString().slice(0, 10);
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;
  
  const body = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: {
        compositeFilter: {
          op: "AND",
          filters: [
            {
              fieldFilter: {
                field: { fieldPath: "timestamp" },
                op: "GREATER_THAN_OR_EQUAL",
                value: { stringValue: dateStr }
              }
            },
            {
              fieldFilter: {
                field: { fieldPath: "timestamp" },
                op: "LESS_THAN",
                value: { stringValue: nextDay }
              }
            }
          ]
        }
      },
      orderBy: [{ field: { fieldPath: "timestamp" }, direction: "ASCENDING" }],
      limit: 1000
    }
  };

  const res = await fetch(url, { 
    method: "POST", 
    headers: { "Content-Type": "application/json" }, 
    body: JSON.stringify(body) 
  });
  
  const data = await res.json();
  const docs = Array.isArray(data) ? data.filter(item => item.document).map(item => item.document) : [];
  console.log(`✅ Found ${docs.length} documents for ${dateStr}.`);
  
  if (docs.length > 0) {
    const locations = Array.from(new Set(docs.map(d => d.fields.location?.stringValue || "MISSING")));
    console.log("Distinct locations found:", locations);
  }
}

testQuery("mega_fit_logs", "2026-04-15").catch(console.error);
