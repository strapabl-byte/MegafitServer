require('dotenv').config();

const DOOR_PROJECT = process.env.DOOR_FIREBASE_PROJECT_ID || 'megadoor-b3ccb';
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY;
const DOOR_URL = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;

// Check yesterday
const yesterday = new Date(Date.now() + 3600000 - 86400000).toISOString().slice(0, 10);
const dayBefore  = new Date(Date.now() + 3600000 - 2 * 86400000).toISOString().slice(0, 10);

async function fetchLastDoc(collectionId, gymLabel, dateStr) {
  const nextDay = new Date(new Date(dateStr).getTime() + 86400000).toISOString().slice(0, 10);
  const body = {
    structuredQuery: {
      from: [{ collectionId }],
      where: {
        compositeFilter: {
          op: 'AND',
          filters: [
            { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: dateStr } } },
            { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'LESS_THAN',             value: { stringValue: nextDay  } } },
          ]
        }
      },
      orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
      limit: 1
    }
  };

  const res  = await fetch(DOOR_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json();

  if (!Array.isArray(data) || !data[0]?.document) {
    console.log(`⚠️  ${gymLabel} (${collectionId}) [${dateStr}]: No docs found`);
    return;
  }

  const f = data[0].document.fields || {};
  console.log(`\n========= ${gymLabel} — ${collectionId} [${dateStr}] =========`);
  console.log('📋 ALL FIELDS IN LAST DOCUMENT:');
  Object.entries(f).forEach(([key, val]) => {
    const value = val.stringValue ?? val.integerValue ?? val.doubleValue ?? val.booleanValue ?? JSON.stringify(val);
    console.log(`   ${key.padEnd(20)}: ${value}`);
  });
}

async function main() {
  console.log(`🔍 Fetching last entry for: ${yesterday} and ${dayBefore}\n`);

  // Fès Dokarat
  await fetchLastDoc('mega_fit_logs', 'FÈS DOKARAT', yesterday);

  // Fès Saiss
  await fetchLastDoc('saiss entrees logs', 'FÈS SAISS', yesterday);
}

main().catch(console.error);
