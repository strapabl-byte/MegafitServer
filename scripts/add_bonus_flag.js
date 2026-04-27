'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const admin = require('firebase-admin');

const serviceAccount = require('../serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

async function main() {
  console.log('Fetching Dokarat archive members...');

  const locations = ['dokkarat fes', 'dokarat', 'dokkarat'];
  let totalUpdated = 0;
  let batch = db.batch();
  let operationCount = 0;

  const snapshot = await db.collection('members')
    .where('location', 'in', locations)
    .where('isArchive', '==', true)
    .get();

  if (snapshot.empty) {
    console.log('No matching members found.');
    process.exit(0);
  }

  for (const doc of snapshot.docs) {
    const data = doc.data();
    if (data.expiresOn) {
      batch.update(doc.ref, { bonus3Months: true });
      operationCount++;
      totalUpdated++;

      if (operationCount >= 400) {
        await batch.commit();
        console.log(`Committed ${totalUpdated} updates...`);
        batch = db.batch();
        operationCount = 0;
      }
    }
  }

  if (operationCount > 0) {
    await batch.commit();
  }

  console.log(`Done! Added bonus3Months flag to ${totalUpdated} members.`);
  process.exit(0);
}

main().catch(console.error);
