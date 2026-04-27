const fs = require('fs');
const lines = fs.readFileSync('c:/Users/Thatsme/Documents/MegaSolution/odoo/eligible_members_doukkarate.csv', 'utf8').split('\n');
const header = lines[0].split(',');
const startIdx = header.indexOf('subs_start');
let err = 0;
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
  let d = new Date(vals[startIdx]);
  if(d > new Date('2025-10-31T00:00:00Z')) {
    console.log('Violating row:', lines[i]);
    err++;
  }
}
console.log('Total violations:', err);
