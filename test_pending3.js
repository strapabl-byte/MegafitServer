require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
const db = admin.firestore();

async function main() {
  const snap = await db.collection('pending_members')
    .where('status', 'in', ['pending', 'awaiting_payment'])
    .get();
    
  snap.docs.forEach(d => {
    const data = d.data();
    if (data.commercial === 'SAHAR' || data.gymId === 'casa2' || data.gymId === 'casa1') {
        console.log(d.id, data.prenom, data.nom, data.gymId, data.status, data.commercial, new Date(data.createdAt._seconds * 1000).toLocaleString());
    }
  });
  process.exit();
}
main();
