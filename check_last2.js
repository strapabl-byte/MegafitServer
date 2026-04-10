// check_last2.js — fetch last 2 raw entries from BOTH gyms
const DOOR_PROJECT = 'megadoor-b3ccb';
const DOOR_API_KEY = 'AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8';

// Morocco time = UTC+1
const now = new Date();
now.setTime(now.getTime() + 60 * 60 * 1000);
const todayStr = now.toISOString().slice(0, 10);
console.log('Today (Morocco):', todayStr);

const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;

async function checkGym(label, collectionId) {
  const body = {
    structuredQuery: {
      from: [{ collectionId }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'timestamp' },
          op: 'GREATER_THAN_OR_EQUAL',
          value: { stringValue: todayStr }
        }
      },
      orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
      limit: 2
    }
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await res.json();

  console.log(`\n${'='.repeat(50)}`);
  console.log(`🏋️  ${label} (collection: ${collectionId})`);
  console.log('='.repeat(50));

  if (!Array.isArray(data) || !data[0]?.document) {
    console.log('  ⚠️  No entries today or unexpected format');
    console.log('  Raw:', JSON.stringify(data).slice(0, 200));
    return;
  }

  data.forEach((item, i) => {
    if (!item.document) return;
    const docId = item.document.name.split('/').pop();
    const f = item.document.fields || {};
    console.log(`\n  --- Entry ${i + 1} (doc: ${docId}) ---`);

    // Key fields first
    const priority = ['name', 'user_id', 'timestamp', 'status', 'method', 'location', 'daily_unique', 'daily_total', 'pushed_at'];
    const allKeys = [...new Set([...priority, ...Object.keys(f)])];

    for (const k of allKeys) {
      if (!f[k]) continue;
      const v = f[k];
      const val =
        v.stringValue  !== undefined ? v.stringValue :
        v.integerValue !== undefined ? `${v.integerValue} (integer)` :
        v.doubleValue  !== undefined ? `${v.doubleValue} (double)` :
        v.booleanValue !== undefined ? String(v.booleanValue) :
        v.timestampValue !== undefined ? v.timestampValue :
        JSON.stringify(v);

      const highlight = (k === 'daily_unique' || k === 'daily_total') ? ' ✅' : '';
      console.log(`    ${k}: ${val}${highlight}`);
    }
  });
}

async function run() {
  await checkGym('Dokkarat Fès', 'mega_fit_logs');
  await checkGym('Fès Saiss (Marjane)', 'saiss entrees logs');
  console.log('\n');
}

run().catch(console.error);
