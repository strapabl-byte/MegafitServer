const fetch = require('node-fetch');

async function check() {
  const DOOR_URL = 'https://firestore.googleapis.com/v1/projects/megadoor-b3ccb/databases/(default)/documents:runQuery';
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'mega_fit_logs' }],
      orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
      limit: 5,
    }
  };

  const resp = await fetch(DOOR_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  
  const data = await resp.json();
  const docs = data.filter(item => item.document).map(item => item.document);
  
  docs.forEach(doc => {
    const f = doc.fields || {};
    console.log(`[${f.timestamp?.stringValue}] ${f.name?.stringValue} | Unique: ${f.daily_unique?.integerValue || f.daily_unique?.doubleValue} | Total: ${f.daily_total?.integerValue || f.daily_total?.doubleValue}`);
  });
}

check();
