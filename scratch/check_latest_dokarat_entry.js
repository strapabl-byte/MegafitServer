'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const DOOR_PROJECT = 'megadoor-b3ccb';
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY;
const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;

const body = {
  structuredQuery: {
    from: [{ collectionId: 'mega_fit_logs' }],
    orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
    limit: 5
  }
};

async function run() {
  const res  = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json();

  const docs = data.filter(x => x.document);
  if (!docs.length) { console.log('No entries found.'); return; }

  docs.forEach((item, i) => {
    const f    = item.document.fields || {};
    const docId = item.document.name?.split('/').pop();
    console.log(`\n========= Entry ${i + 1} (docId: ${docId}) =========`);
    Object.entries(f).forEach(([k, v]) => {
      const val =
        v.stringValue    !== undefined ? v.stringValue    :
        v.integerValue   !== undefined ? v.integerValue   :
        v.doubleValue    !== undefined ? v.doubleValue    :
        v.booleanValue   !== undefined ? v.booleanValue   :
        v.timestampValue !== undefined ? v.timestampValue :
        JSON.stringify(v);
      console.log(`  ${k}: ${val}`);
    });
  });
}

run().catch(e => { console.error('Error:', e.message); process.exit(1); });
