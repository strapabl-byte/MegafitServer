'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();
const fs = require('fs');

async function run() {
  const lines = fs.readFileSync('c:/Users/Thatsme/Documents/MegaSolution/odoo/eligible_members_doukkarate.csv', 'utf8').split('\n');
  const header = lines[0].split(',').map(h => h.replace(/^\uFEFF/, '').trim());
  const nameIdx = header.indexOf('full_name');
  
  let foundInFirebase = 0;
  let hasBonus = 0;
  let missingBonus = 0;
  let notFound = 0;

  console.log('Querying Firebase (Production) to check 1094 members... This might take a minute.');

  // Group into batches to avoid rate limits
  for(let i=1; i<lines.length; i+=10) {
    const batch = lines.slice(i, i+10);
    const promises = batch.map(async (line) => {
      if(!line.trim()) return;
      let vals = [];
      let inQ = false, val = '';
      for(let c of line) {
        if(c==='\"') inQ=!inQ;
        else if(c===',' && !inQ) { vals.push(val); val=''; }
        else val+=c;
      }
      vals.push(val);
      if(!vals[nameIdx]) return;
      
      let name = vals[nameIdx].replace(/"/g, '').trim();
      
      // Query Firebase
      try {
        const snap = await db.collection('members')
          .where('fullName', '==', name)
          .limit(1)
          .get();
          
        if (!snap.empty) {
          foundInFirebase++;
          const data = snap.docs[0].data();
          if (data.bonus3Months === true) hasBonus++;
          else missingBonus++;
        } else {
          // Try a broad search by fetching all and filtering? Too expensive.
          // Odoo imports usually have the exact fullName.
          notFound++;
        }
      } catch (err) {
        console.error("Error querying", name);
      }
    });
    
    await Promise.all(promises);
    process.stdout.write(`\rProcessed ${Math.min(i+10, lines.length)} / ${lines.length}`);
  }

  console.log(`\n\nTotal in CSV: ${lines.length - 1}`);
  console.log(`Found in Firebase: ${foundInFirebase}`);
  console.log(`- With Bonus +3M: ${hasBonus}`);
  console.log(`- Missing Bonus: ${missingBonus}`);
  console.log(`Not found in Firebase: ${notFound}`);
  process.exit(0);
}

run().catch(console.error);
