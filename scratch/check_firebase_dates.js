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
  const stopIdx = header.indexOf('subs_stop');

  let checked = 0;
  let dateMatches = 0;
  let dateIsShifted = 0;
  let missing = 0;

  console.log('Comparing Odoo CSV expiration dates vs Firebase expiration dates...');

  for(let i=1; i<lines.length; i+=20) {
    const batch = lines.slice(i, i+20);
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
      let csvDateStr = vals[stopIdx].replace(/"/g, '').trim();
      
      try {
        const snap = await db.collection('members').where('fullName', '==', name).limit(1).get();
        if (!snap.empty) {
          checked++;
          const data = snap.docs[0].data();
          const fbDateStr = data.expiresOn || '';
          
          if (fbDateStr) {
            let csvD = new Date(csvDateStr);
            let fbD = new Date(fbDateStr);
            let diffDays = (fbD - csvD) / (1000*60*60*24);
            
            if (Math.abs(diffDays) < 10) {
               dateMatches++; // The dates are basically the same (no +3 months added)
            } else if (diffDays >= 80) {
               dateIsShifted++; // The Firebase date is ~3 months after the Odoo date!
            } else {
               // Something else
            }
          }
        }
      } catch (err) {}
    });
    
    await Promise.all(promises);
    process.stdout.write(`\rProcessed ${Math.min(i+20, lines.length)} / ${lines.length}`);
  }

  console.log(`\n\nChecked in Firebase: ${checked}`);
  console.log(`Dates match Odoo (no time added): ${dateMatches}`);
  console.log(`Dates shifted by ~3 months in Firebase: ${dateIsShifted}`);
  process.exit(0);
}

run().catch(console.error);
