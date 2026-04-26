// scripts/export_members_seed.js
// Converts the Odoo CSV directly to a JSON seed file for Render.
// No Firebase reads needed. Run: node scripts/export_members_seed.js

'use strict';
const fs   = require('fs');
const path = require('path');

const CSV_PATH = path.join(__dirname, '..', '..', 'odoo', 'members_fes_doukkarate.csv');
const OUT_PATH = path.join(__dirname, '..', 'seed_members_dokarat.json');

function parseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/).filter(l => l.trim());
  const headers = lines[0].split(',').map(h => h.trim());
  return lines.slice(1).map(line => {
    const cols = [];
    let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { inQ = !inQ; }
      else if (c === ',' && !inQ) { cols.push(cur); cur = ''; }
      else { cur += c; }
    }
    cols.push(cur);
    const obj = {};
    headers.forEach((h, i) => { obj[h] = (cols[i] || '').replace(/\t/g, ' ').trim(); });
    return obj;
  });
}

function mapStatus(s) {
  if (!s) return 'inactive';
  const l = s.toLowerCase();
  if (l.includes('active') && !l.includes('expired') && !l.includes('inactive')) return 'active';
  if (l.includes('expired') || l.includes('inactive')) return 'inactive';
  return 'draft';
}

console.log(`📂 Reading: ${CSV_PATH}`);
const rows = parseCSV(CSV_PATH);
console.log(`📋 Rows: ${rows.length}`);

const members = rows.map(row => {
  const fullName = `${row.firstname || ''} ${row.lastname || ''}`.trim()
    || row.full_name?.replace(/\s+/g, ' ').trim() || '';
  if (!fullName) return null;

  return {
    fullName,
    firstName:         row.firstname || '',
    lastName:          row.lastname  || '',
    email:             row.email     || '',
    phone:             (row.mobile || row.phone || '').replace(/\s+/g, ''),
    location:          'dokkarat fes',
    status:            mapStatus(row.status),
    odooStatus:        row.status || '',
    isArchive:         true,
    importedFromOdoo:  true,
    birthday:          (row.x_birthday && row.x_birthday !== '1900-01-01' && row.x_birthday !== '1900-06-06') ? row.x_birthday : null,
    subscriptionStart: row.subs_start       || null,
    expiresOn:         row.subs_stop        || null,
    totalPaid:         row.total_paid       ? parseFloat(row.total_paid) : 0,
    lastPaymentDate:   row.last_payment_date || null,
    createdAt:         row.subs_start       || null,
  };
}).filter(Boolean);

fs.writeFileSync(OUT_PATH, JSON.stringify(members, null, 0)); // compact JSON
const sizeKB = Math.round(fs.statSync(OUT_PATH).size / 1024);
console.log(`✅ Exported ${members.length} members to seed_members_dokarat.json (${sizeKB} KB)`);
