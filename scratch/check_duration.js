const fs = require('fs');
const lines = fs.readFileSync('c:/Users/Thatsme/Documents/MegaSolution/odoo/eligible_members_doukkarate.csv', 'utf8').split('\n');
const header = lines[0].split(',');
const startIdx = header.indexOf('subs_start');
const stopIdx = header.indexOf('subs_stop');

let under6 = 0;
let over6 = 0;

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
  
  let dStart = new Date(vals[startIdx]);
  let dStop = new Date(vals[stopIdx]);

  let diffDays = (dStop - dStart) / (1000 * 60 * 60 * 24);

  if (diffDays >= 170) {
    over6++;
  } else {
    under6++;
  }
}
console.log('>= 6 months:', over6);
console.log('< 6 months:', under6);
