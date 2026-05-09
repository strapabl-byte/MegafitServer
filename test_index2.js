require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
const db = admin.firestore();

async function main() {
  try {
    const snap = await db.collection('pending_members')
      .where('source', '==', 'web')
      .where('status', 'in', ['pending', 'awaiting_payment'])
      .where('gymId', '==', 'casa2')
      .get();
      
    snap.docs.forEach(d => {
      console.log(d.id, d.data().prenom, d.data().nom, "payment_validated:", d.data().payment_validated);
    });
  } catch (err) {
    console.error('ERROR:', err.message);
  }
  process.exit();
}
main();
