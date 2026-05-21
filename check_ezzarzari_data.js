const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');
if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

async function run() {
  // Check pending_member (inscription)
  const insSnap = await db.collection('pending_members').where('contractNumber', '==', '016058').get();
  insSnap.forEach(doc => {
    const d = doc.data();
    console.log('=== INSCRIPTION (pending_members) ===');
    console.log(`  ID: ${doc.id}`);
    console.log(`  totals:`, JSON.stringify(d.totals));
    console.log(`  payments:`, JSON.stringify(d.payments));
    console.log(`  memberId: ${d.memberId}`);
    console.log(`  status: ${d.status}`);
  });

  // Check member
  const memberSnap = await db.collection('members').where('contractNumber', '==', '016058').get();
  memberSnap.forEach(doc => {
    const d = doc.data();
    console.log('\n=== MEMBER ===');
    console.log(`  ID: ${doc.id}`);
    console.log(`  fullName: ${d.fullName}`);
    console.log(`  balance: ${d.balance}`);
    console.log(`  balanceDeadline: ${d.balanceDeadline}`);
  });

  // Check payments
  const paySnap = await db.collection('payments').where('memberId', '==', 'k77ie85viawdEqlkEHLu').get();
  paySnap.forEach(doc => {
    const d = doc.data();
    console.log('\n=== PAYMENT ===');
    console.log(`  amount: ${d.amount}, method: ${d.method}, type: ${d.type}`);
    console.log(`  paymentsSplit:`, JSON.stringify(d.paymentsSplit));
  });
}

run().catch(console.error);
