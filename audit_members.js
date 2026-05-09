require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
const db = admin.firestore();

async function main() {
  console.log('=== AUDIT: members collection for cross-gym contamination ===\n');
  const snap = await db.collection('members').limit(500).get();
  
  const validGyms = ['dokarat', 'marjane', 'casa1', 'casa2'];
  const byGym = { dokarat: 0, marjane: 0, casa1: 0, casa2: 0, unknown: 0 };
  const issues = [];
  const cinMap = {};
  
  snap.docs.forEach(d => {
    const data = d.data();
    const gymId = data.gymId || data.location || 'MISSING';
    
    if (!validGyms.includes(gymId)) {
      issues.push({ id: d.id, fullName: data.fullName, gymId });
      byGym.unknown++;
    } else {
      byGym[gymId]++;
    }
    
    if (data.cin) {
      if (!cinMap[data.cin]) cinMap[data.cin] = [];
      cinMap[data.cin].push({ id: d.id, gymId, fullName: data.fullName });
    }
  });
  
  console.log('=== GYM DISTRIBUTION (members) ===');
  Object.entries(byGym).forEach(([gym, count]) => console.log(`${gym}: ${count}`));
  
  console.log(`\nTotal members scanned: ${snap.docs.length}`);
  
  if (issues.length > 0) {
    console.log('\n=== MEMBERS WITH UNKNOWN/MISSING GYM ===');
    issues.slice(0, 20).forEach(m => console.log(JSON.stringify(m)));
  } else {
    console.log('\nNO GYM MISSING — all members have valid gymId');
  }
  
  console.log('\n=== CROSS-GYM CIN CHECK (members) ===');
  let conflicts = 0;
  Object.entries(cinMap).forEach(([cin, records]) => {
    const gyms = new Set(records.map(r => r.gymId));
    if (gyms.size > 1) {
      conflicts++;
      console.log('CONFLICT CIN', cin, ':', JSON.stringify(records));
    }
  });
  if (conflicts === 0) console.log('NO CONFLICTS — Clean');
  
  process.exit(0);
}
main().catch(console.error);
