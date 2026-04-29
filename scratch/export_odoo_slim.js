// scratch/export_odoo_slim.js
// Run: node scratch/export_odoo_slim.js
// Generates data/odoo_members_slim.json for the server to load into SQLite

const fs   = require('fs');
const path = require('path');

const CSV_PATH  = path.join(__dirname, '../../odoo/all_members_all_clubs.csv');
const OUT_PATH  = path.join(__dirname, '../data/odoo_members_slim.json');

const GYM_MAP = {
  'FES DOUKKARATE': 'dokarat',
  'FES MARJANE':    'marjane',
  'CASA 1':         'casa1',
  'CASA 2':         'casa2',
};

const raw = fs.readFileSync(CSV_PATH, 'utf8');
const lines = raw.split('\n').slice(1); // skip header

const members = [];
for (const line of lines) {
  if (!line.trim()) continue;
  // CSV: full_name,firstname,lastname,email,mobile,phone,club,status,subs_start,subs_stop,...
  const cols = line.split(',');
  if (cols.length < 10) continue;

  const fullName   = (cols[0] || '').trim().toUpperCase();
  const firstName  = (cols[1] || '').trim().toUpperCase();
  const lastName   = (cols[2] || '').trim().toUpperCase();
  const club       = (cols[6] || '').trim().toUpperCase();
  const status     = (cols[7] || '').trim();
  const expiresOn  = (cols[9] || '').trim();
  const gymId      = GYM_MAP[club] || null;

  if (!fullName || !gymId) continue;

  members.push({ fullName, firstName, lastName, gymId, status, expiresOn });
}

fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
fs.writeFileSync(OUT_PATH, JSON.stringify(members), 'utf8');
console.log(`✅ Exported ${members.length} members → ${OUT_PATH}`);
console.log('   Gyms:', [...new Set(members.map(m => m.gymId))].join(', '));
