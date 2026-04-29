require('dotenv').config();
const admin = require('firebase-admin');
const sa = require('../serviceAccount.json');
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });

const projectId = process.env.DOOR_PROJECT_ID || 'megadokarat';
console.log('🔑 Door project ID:', projectId);

(async () => {
  const token = await admin.app().options.credential.getAccessToken();
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`;

  const body = {
    structuredQuery: {
      from: [{ collectionId: 'mega_fit_logs' }],
      orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
      limit: 1
    }
  };

  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const data = await r.json();
  console.log('🔥 LAST ENTRY FROM FIREBASE (mega_fit_logs / dokarat):');
  if (Array.isArray(data) && data[0]?.document) {
    const doc = data[0].document;
    const fields = Object.fromEntries(
      Object.entries(doc.fields || {}).map(([k, v]) => [k, Object.values(v)[0]])
    );
    console.log({ docId: doc.name?.split('/').pop(), ...fields });
  } else {
    console.log(JSON.stringify(data, null, 2).slice(0, 1500));
  }
  process.exit(0);
})();
