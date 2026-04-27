'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const admin = require('firebase-admin');

// Initialize Firebase
const serviceAccount = require('../serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

// Helper to add months to a YYYY-MM-DD string
function addMonthsToDateStr(dateStr, months) {
  if (!dateStr || dateStr.length < 10) return dateStr;
  
  // dateStr is 'YYYY-MM-DD' or similar
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return dateStr;

    // Add months
    date.setMonth(date.getMonth() + months);
    
    // Return in YYYY-MM-DD format
    return date.toISOString().slice(0, 10);
  } catch (err) {
    return dateStr;
  }
}

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

  console.log(`Found ${snapshot.docs.length} archive members for Dokarat.`);

  for (const doc of snapshot.docs) {
    const data = doc.data();
    
    if (data.expiresOn) {
      const oldDate = data.expiresOn;
      const newDate = addMonthsToDateStr(oldDate, 3);
      
      if (oldDate !== newDate) {
        batch.update(doc.ref, {
          expiresOn: newDate
        });
        
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
  }

  if (operationCount > 0) {
    await batch.commit();
    console.log(`Committed ${totalUpdated} total updates.`);
  }

  console.log('Done!');
  process.exit(0);
}

main().catch(console.error);
