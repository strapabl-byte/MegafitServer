const fs = require('fs');
const lc = require('../localCache');

const lines = fs.readFileSync('c:/Users/Thatsme/Documents/MegaSolution/odoo/eligible_members_doukkarate.csv', 'utf8').split('\n');
const header = lines[0].split(',').map(h => h.replace(/^\uFEFF/, '').trim());
const nameIdx = header.indexOf('full_name');
const phoneIdx = header.indexOf('mobile');
console.log('Header:', header);
console.log('Name Idx:', nameIdx);

let foundInSqlite = 0;
let hasBonus = 0;
let missingBonus = 0;
let notFound = 0;

for(let i=1; i<lines.length; i++) {
  if(!lines[i].trim()) continue;
  let vals = [];
  let inQ = false, val = '';
  for(let c of lines[i]) {
    if(c==='\"') inQ=!inQ;
    else if(c===',' && !inQ) { vals.push(val); val=''; }
    else val+=c;
  }
  vals.push(val);
  
  if(!vals[nameIdx]) continue;
  let name = vals[nameIdx].replace(/"/g, '').trim();
  let phone = (vals[phoneIdx] || '').replace(/"/g, '').trim();

  // Try to find in SQLite
  let row = lc.db.prepare(`SELECT * FROM members_cache WHERE full_name = ? OR phone = ?`).get(name, phone);
  
  if (row) {
    foundInSqlite++;
    if (row.bonus_3months === 1) {
      hasBonus++;
    } else {
      missingBonus++;
    }
  } else {
    // Try LIKE query for name
    row = lc.db.prepare(`SELECT * FROM members_cache WHERE full_name LIKE ? LIMIT 1`).get(`%${name}%`);
    if (row) {
      foundInSqlite++;
      if (row.bonus_3months === 1) hasBonus++;
      else missingBonus++;
    } else {
      notFound++;
    }
  }
}

console.log(`Total in CSV: ${lines.length - 1}`);
console.log(`Found in SQLite DB: ${foundInSqlite}`);
console.log(`- With Bonus +3M: ${hasBonus}`);
console.log(`- Missing Bonus: ${missingBonus}`);
console.log(`Not found in DB: ${notFound}`);
