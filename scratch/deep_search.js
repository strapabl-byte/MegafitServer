
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function deepSearch() {
  const term = 'Bouchaib';
  console.log(`🕵️ Deep searching for "${term}" in all likely collections...`);
  
  const collections = ['members', 'pending_members', 'payments', 'megafit_daily_register'];
  
  for (const coll of collections) {
    const snap = await db.collection(coll).get();
    const matches = snap.docs.filter(doc => JSON.stringify(doc.data()).includes(term));
    console.log(`- Collection "${coll}": Found ${matches.length} matches.`);
    matches.forEach(doc => {
      console.log(`  [MATCH] ${doc.id} (Ref: ${doc.ref.path})`);
    });
  }
  process.exit(0);
}

deepSearch();
