require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
const db = admin.firestore();

async function main() {
  const snap = await db.collection('pending_members').orderBy('createdAt', 'desc').limit(20).get();
  snap.docs.forEach(d => {
    const data = d.data();
    console.log(d.id, data.prenom, data.nom, data.gymId, data.status, data.commercial);
  });
  process.exit();
}
main();
