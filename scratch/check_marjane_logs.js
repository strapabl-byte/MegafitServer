
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

async function fetchLatestDocs(collectionName) {
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      orderBy: [{ field: { fieldPath: "timestamp" }, direction: "DESCENDING" }],
      limit: 10
    }
  };

  try {
    const res = await fetch(url, { 
      method: "POST", 
      headers: { "Content-Type": "application/json" }, 
      body: JSON.stringify(body) 
    });
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    return data.filter(i => i.document).map(i => i.document);
  } catch (err) {
    console.error(`Error fetching ${collectionName}:`, err.message);
    return [];
  }
}

async function run() {
  const today = new Date().toISOString().slice(0, 10);
  console.log(`Checking Marjane logs for project: ${DOOR_PROJECT}`);

  const collections = ["saiss entrees logs", "mega_fit_logs"];
  
  for (const coll of collections) {
    console.log(`\n--- ${coll.toUpperCase()} ---`);
    const docs = await fetchLatestDocs(coll);
    
    if (docs.length === 0) {
      console.log("No recent logs found.");
      continue;
    }

    docs.forEach(doc => {
      const f = doc.fields || {};
      const loc = f.location?.stringValue || "Unknown";
      
      // Filter for Marjane/Saiss
      const isMarjane = loc.toLowerCase().includes("saiss") || loc.toLowerCase().includes("marjane");
      if (!isMarjane && coll === "mega_fit_logs") return;

      const time = f.timestamp?.stringValue || "Unknown";
      const userId = f.id?.stringValue || f.memberId?.stringValue || "N/A";
      const unique = f.daily_unique?.integerValue || "N/A";
      const total = f.daily_total?.integerValue || "N/A";
      
      console.log(`${time} | ${loc} | User: ${userId} | DeviceCounters: [U:${unique}, T:${total}]`);
    });
  }
}

run();
