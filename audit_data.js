require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
const db = admin.firestore();

async function main() {
  console.log('=== FULL AUDIT: Pending Members with wrong gymId or missing gymId ===\n');

  const snap = await db.collection('pending_members').get();
  
  const validGyms = ['dokarat', 'marjane', 'casa1', 'casa2'];
  const issues = [];
  const byGym = { dokarat: 0, marjane: 0, casa1: 0, casa2: 0, unknown: 0 };
  
  snap.docs.forEach(d => {
    const data = d.data();
    const gymId = data.gymId || 'MISSING';
    const status = data.status || 'MISSING';
    const source = data.source || 'MISSING';
    
    if (!validGyms.includes(gymId)) {
      issues.push({ id: d.id, prenom: data.prenom, nom: data.nom, gymId, status, source });
      byGym.unknown++;
    } else {
      byGym[gymId]++;
    }
  });
  
  console.log('=== GYM DISTRIBUTION ===');
  Object.entries(byGym).forEach(([gym, count]) => {
    console.log(`${gym}: ${count} inscriptions`);
  });
  
  console.log('\n=== MEMBERS WITH UNKNOWN/MISSING GYM ===');
  if (issues.length === 0) {
    console.log('NO ISSUES — all pending inscriptions have valid gym IDs');
  } else {
    issues.forEach(m => console.log(JSON.stringify(m)));
  }

  console.log('\n=== CASA2 PENDING (ALL) ===');
  const casa2 = await db.collection('pending_members').where('gymId', '==', 'casa2').get();
  casa2.docs.forEach(d => {
    const data = d.data();
    console.log({
      id: d.id, prenom: data.prenom, nom: data.nom, status: data.status,
      commercial: data.commercial, source: data.source, 
      gymId: data.gymId,
      subscriptionName: data.subscriptionName,
      createdAt: data.createdAt?._seconds ? new Date(data.createdAt._seconds * 1000).toISOString() : 'N/A'
    });
  });

  console.log('\n=== CROSS-GYM CIN CONTAMINATION CHECK ===');
  const cinMap = {};
  snap.docs.forEach(d => {
    const data = d.data();
    if (data.cin) {
      if (!cinMap[data.cin]) cinMap[data.cin] = [];
      cinMap[data.cin].push({ id: d.id, gymId: data.gymId, nom: data.nom, status: data.status });
    }
  });
  let conflicts = 0;
  Object.entries(cinMap).forEach(([cin, records]) => {
    const gyms = new Set(records.map(r => r.gymId));
    if (gyms.size > 1) {
      conflicts++;
      console.log('CONFLICT CIN', cin, ':', JSON.stringify(records));
    }
  });
  if (conflicts === 0) console.log('NO CONFLICTS — No CIN appears in multiple gyms');
  
  process.exit(0);
}
main().catch(console.error);
