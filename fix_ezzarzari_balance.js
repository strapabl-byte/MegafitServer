const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');
if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();
const Database = require('better-sqlite3');
const cacheDb = new Database('megafit_cache.db');

async function run() {
  const memberId = 'lXQFMainvHKl1XTpfxlo';
  const correctBalance = 1900;

  // Fix Firestore
  await db.collection('members').doc(memberId).update({
    balance: correctBalance,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });
  console.log(`✅ Firestore member balance updated to ${correctBalance} DH`);

  // Fix SQLite
  try {
    cacheDb.prepare('UPDATE members_cache SET balance = ? WHERE id = ?').run(correctBalance, memberId);
    console.log(`✅ SQLite members_cache balance updated to ${correctBalance} DH`);
  } catch (e) {
    console.warn('SQLite update failed:', e.message);
  }

  // Verify
  const doc = await db.collection('members').doc(memberId).get();
  console.log(`\nVerification: member.balance = ${doc.data().balance} DH`);
}

run().catch(console.error);
