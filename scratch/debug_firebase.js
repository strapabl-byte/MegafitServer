const fetch = require('node-fetch');

async function check() {
  const DOOR_URL = 'https://firestore.googleapis.com/v1/projects/megafitauth/databases/(default)/documents:runQuery';
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'doukkarate_door_entries' }],
      orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
      limit: 10,
    }
  };

  const resp = await fetch(DOOR_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  
  const data = await resp.json();
  console.log(JSON.stringify(data, null, 2));
}

check();
