require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
const db = admin.firestore();

async function main() {
  const snap = await db.collection('pending_members').get();
  snap.docs.forEach(d => {
    const data = d.data();
    if (data.status === 'pending' || data.status === 'awaiting_payment') {
      console.log(d.id, data.prenom, data.nom, data.gymId, data.createdAt?._seconds ? new Date(data.createdAt._seconds * 1000).toLocaleString() : 'N/A');
    }
  });
  process.exit();
}
main();
