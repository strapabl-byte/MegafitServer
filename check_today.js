
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

async function countToday(collectionName, locationTags, dateStr) {
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
      limit: 2000
    }
  };

  const res = await fetch(url, { 
    method: "POST", 
    headers: { "Content-Type": "application/json" }, 
    body: JSON.stringify(body) 
  });
  
  const data = await res.json();
  const docs = Array.isArray(data) ? data.filter(item => item.document).map(item => item.document) : [];
  
  const tags = locationTags.map(t => t.toLowerCase().trim());
  const filtered = docs.filter(doc => {
    const loc = (doc.fields.location?.stringValue || "").toLowerCase().trim();
    return tags.some(t => loc === t || loc.includes(t) || t.includes(loc));
  });

  const sorted = [...filtered].sort((a,b) => 
    (a.fields.timestamp?.stringValue || "").localeCompare(b.fields.timestamp?.stringValue || "")
  );

  const seen = new Map();
  let unique = 0;
  for (const doc of sorted) {
    const f   = doc.fields;
    const uid = f.user_id?.stringValue || f.id?.stringValue || doc.name.split("/").pop();
    const t   = new Date(f.timestamp?.stringValue || 0).getTime();
    if (!seen.has(uid) || Math.abs(t - seen.get(uid)) >= 600000) {
      unique++;
      seen.set(uid, t);
    }
  }

  return { unique, raw: filtered.length };
}

async function run() {
  const today = "2026-04-16";
  console.log(`🔍 Counting entries for ${today}...`);
  
  const dokarat = await countToday("mega_fit_logs", ["dokkarat fes"], today);
  console.log(`🏟️  Dukkarate: ${dokarat.unique} unique (${dokarat.raw} raw)`);
  
  const marjane = await countToday("saiss entrees logs", ["fes saiss", "fes marjane"], today);
  // Also check mega_fit_logs for marjane as fallback
  const marjaneExtra = await countToday("mega_fit_logs", ["fes saiss", "fes marjane"], today);
  
  console.log(`🏟️  Marjane: ${marjane.unique + marjaneExtra.unique} unique (${marjane.raw + marjaneExtra.raw} raw)`);
}

run().catch(console.error);
