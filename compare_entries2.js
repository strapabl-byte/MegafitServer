const fetch = (...a) => import('node-fetch').then(({default:f})=>f(...a));
require('dotenv').config();
const DOOR_PROJECT_ID = process.env.DOOR_FIREBASE_PROJECT_ID || 'megadoor-b3ccb';
const DOOR_REST_KEY = process.env.DOOR_FIREBASE_API_KEY;
const TODAY = new Date().toISOString().slice(0,10);

async function run() {
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT_ID}/databases/(default)/documents:runQuery?key=${DOOR_REST_KEY}`;
  
  // Firebase direct with limit=1000
  const body = { structuredQuery: { from:[{collectionId:'mega_fit_logs'}], where:{ fieldFilter:{ field:{fieldPath:'location'}, op:'EQUAL', value:{stringValue:'dokkarat fes'} }}, limit:1000 }};
  const r = await fetch(url, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data = await r.json();
  const allDocs = (data).filter(x=>x.document).map(x=>{
    const f = x.document.fields||{};
    const pushedAt = f.pushed_at?.timestampValue;
    const sk = pushedAt ? new Date(pushedAt).toISOString() : (f.timestamp?.stringValue||'');
    return {name: f.name?.stringValue||'?', sk};
  }).filter(d=>d.sk).sort((a,b)=>b.sk.localeCompare(a.sk));
  
  const todayDocs = allDocs.filter(d=>d.sk.startsWith(TODAY));
  
  console.log('=== FIREBASE DIRECT (limit=1000) ===');
  console.log('Total docs:', allDocs.length);
  console.log('Today ('+TODAY+'):', todayDocs.length, 'entries');
  console.log('Last 5:', todayDocs.slice(0,5).map(d=>d.name+' @ '+d.sk.slice(11,16)).join(' | '));
}
run();
