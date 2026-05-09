
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function searchGlobal() {
  const names = ['Wael', 'Rania', 'Souleiman', 'Hoda', 'Ali Rami', 'Mustapha Chafik'];
  
  for (const n of names) {
    console.log(`\n🔍 Searching for "${n}" globally...`);
    const snap = await db.collection('members').get();
    const matches = snap.docs.filter(d => {
      const fn = (d.data().fullName || '').toLowerCase();
      const n1 = (d.data().name || '').toLowerCase();
      const n2 = (d.data().surname || '').toLowerCase();
      return fn.includes(n.toLowerCase()) || n1.includes(n.toLowerCase()) || n2.includes(n.toLowerCase());
    });
    
    console.log(`- Found ${matches.length} matches in members.`);
    for (const doc of matches) {
      const d = doc.data();
      console.log(`  [DELETE?] ${doc.id}: ${d.fullName || d.name + ' ' + d.surname} (Gym: ${d.location})`);
    }

    const snap2 = await db.collection('pending_members').get();
    const matches2 = snap2.docs.filter(d => {
      const fn = (d.data().prenom + ' ' + d.data().nom).toLowerCase();
      return fn.includes(n.toLowerCase());
    });
    console.log(`- Found ${matches2.length} matches in pending_members.`);
    for (const doc of matches2) {
      const d = doc.data();
      console.log(`  [DELETE?] ${doc.id}: ${d.prenom} ${d.nom} (Gym: ${d.gymId})`);
    }
  }
  process.exit(0);
}

searchGlobal();
