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
  console.log('Fetching members with bonus flag to verify registration date...');

  const snapshot = await db.collection('members')
    .where('bonus3Months', '==', true)
    .get();

  if (snapshot.empty) {
    console.log('No members with bonus flag found.');
    process.exit(0);
  }

  let totalRemoved = 0;
  let batch = db.batch();
  let operationCount = 0;

  // Threshold: After October 2025 -> November 1st, 2025
  const thresholdDate = new Date('2025-11-01');

  for (const doc of snapshot.docs) {
    const data = doc.data();
    let inscribedAt = null;

    if (data.createdAt) {
      if (typeof data.createdAt === 'string') {
        inscribedAt = new Date(data.createdAt);
      } else if (data.createdAt.toDate) {
        inscribedAt = data.createdAt.toDate();
      } else if (data.createdAt._seconds) {
        inscribedAt = new Date(data.createdAt._seconds * 1000);
      }
    }

    // If inscribed after Oct 2025, remove the bonus flag
    if (inscribedAt && inscribedAt >= thresholdDate) {
      batch.update(doc.ref, { bonus3Months: admin.firestore.FieldValue.delete() });
      operationCount++;
      totalRemoved++;

      if (operationCount >= 400) {
        await batch.commit();
        console.log(`Committed ${totalRemoved} removals...`);
        batch = db.batch();
        operationCount = 0;
      }
    }
  }

  if (operationCount > 0) {
    await batch.commit();
  }

  console.log(`Done! Removed bonus3Months flag from ${totalRemoved} members who inscribed after Oct 2025.`);
  process.exit(0);
}

main().catch(console.error);
