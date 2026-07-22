/**
 * import_backup_aqsa.js
 * Imports all 13,510 cleaned Odoo members from backup_aqsa_membership_line.csv into:
 *   1. data/odoo_members_slim.json
 *   2. odoo_members_cache SQLite table
 */

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const CSV_PATH  = 'C:/Users/Thatsme/Downloads/Odoo/backup_aqsa_membership_line.csv';
const SLIM_PATH = path.join(__dirname, 'data', 'odoo_members_slim.json');
const DB_PATH   = path.join(__dirname, 'megafit_cache.db');

function normName(s) {
  return (s || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function cleanGymName(rawName, posOrderName) {
  if (!rawName) {
    if (posOrderName && posOrderName.includes('CASA ANFA LADY')) return 'Casa Anfa Lady';
    if (posOrderName && posOrderName.includes('CASA ANFA')) return 'Casa Anfa';
    if (posOrderName && posOrderName.includes('FES')) return 'Fès Marjane';
    return 'Non Spécifié';
  }
  const upper = rawName.toUpperCase();
  if (upper.includes('DOUKKARATE') || upper.includes('DOKARAT')) return 'Fès Dokkarat';
  if (upper.includes('MARJANE') || upper.includes('SAISS')) return 'Fès Marjane';
  if (upper.includes('CASA ANFA LADY') || upper.includes('LADY')) return 'Casa Anfa Lady';
  if (upper.includes('CASA ANFA')) return 'Casa Anfa';
  return rawName.replace(/\s*\([^)]*\)/g, '').trim();
}

function getGymKey(cleanName) {
  switch (cleanName) {
    case 'Fès Dokkarat': return 'dokarat';
    case 'Fès Marjane': return 'marjane';
    case 'Casa Anfa': return 'casa1';
    case 'Casa Anfa Lady': return 'casa2';
    default: return 'other';
  }
}

function parseCSVLine(line) {
  const result = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQuotes = !inQuotes; }
    else if (c === ',' && !inQuotes) { result.push(cur); cur = ''; }
    else { cur += c; }
  }
  result.push(cur);
  return result;
}

console.log('📖 Reading CSV:', CSV_PATH);
const rawText = fs.readFileSync(CSV_PATH, 'utf8');
const lines = rawText.split(/\r?\n/);
const headers = parseCSVLine(lines[0]).map(h => h.replace(/^\uFEFF/, '').trim());

console.log(`   ${lines.length - 1} total rows found in CSV`);

const members = [];
const byGym = {};

for (let i = 1; i < lines.length; i++) {
  const line = lines[i].trim();
  if (!line) continue;
  const cols = parseCSVLine(line);
  const row = {};
  headers.forEach((h, idx) => { row[h] = (cols[idx] || '').trim(); });

  const fullName = (row.partner_name || '').trim().toUpperCase();
  if (!fullName) continue;

  const rawClub = row.club_name || '';
  const posOrder = row.pos_order_name || '';
  const cleanGym = cleanGymName(rawClub, posOrder);
  const gymId = getGymKey(cleanGym);

  const formulaName = row.membership_name || row.pos_order_line_name || '';
  const isUpgrade = formulaName.toUpperCase().includes('UPGRADE') || (row.pos_order_line_name || '').toUpperCase().includes('UPGRADE') ? 1 : 0;

  const nameParts = fullName.split(' ').filter(Boolean);
  const firstName = nameParts.length > 1 ? nameParts[nameParts.length - 1] : '';
  const lastName  = nameParts.length > 1 ? nameParts.slice(0, -1).join(' ') : fullName;

  const status = (row.state || 'inactive').toLowerCase();

  members.push({
    fullName,
    firstName,
    lastName,
    gymId,
    status: status === 'active' ? 'Active' : status === 'futur' ? 'Futur' : 'Expired/Inactive',
    expiresOn: row.date_to || row.date || null,
    dateFrom: row.date_from || null,
    dateInscription: row.date || null,
    membershipName: formulaName,
    amountPaid: parseFloat(row.amount_paid) || 0,
    isUpgrade,
    partnerId: row.partner || null,
    posOrderName: posOrder,
  });

  byGym[gymId] = (byGym[gymId] || 0) + 1;
}

console.log('\n📊 Records by Gym:');
Object.entries(byGym).forEach(([g, count]) => console.log(`   ${g}: ${count}`));
console.log(`   TOTAL PARSED: ${members.length}`);

// 💾 Save data/odoo_members_slim.json
console.log('\n💾 Writing data/odoo_members_slim.json ...');
fs.writeFileSync(SLIM_PATH, JSON.stringify(members, null, 2), 'utf8');
console.log(`   ✅ Saved slim JSON (${(fs.statSync(SLIM_PATH).size / (1024 * 1024)).toFixed(2)} MB)`);

// 🗄️ Reload SQLite cache
console.log('\n🗄️  Updating odoo_members_cache in SQLite...');
const db = new Database(DB_PATH);

// Run migrations first
const migrations = [
  'ALTER TABLE odoo_members_cache ADD COLUMN date_from TEXT',
  'ALTER TABLE odoo_members_cache ADD COLUMN membership_name TEXT',
  'ALTER TABLE odoo_members_cache ADD COLUMN amount_paid REAL DEFAULT 0',
  'ALTER TABLE odoo_members_cache ADD COLUMN is_upgrade INTEGER DEFAULT 0',
];
for (const m of migrations) {
  try { db.prepare(m).run(); } catch (_) {}
}

db.prepare('DELETE FROM odoo_members_cache').run();

const insert = db.prepare(`
  INSERT INTO odoo_members_cache 
  (full_name, first_name, last_name, gym_id, status, expires_on, name_norm, date_from, membership_name, amount_paid, is_upgrade)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAll = db.transaction((rows) => {
  for (const m of rows) {
    insert.run(
      m.fullName, m.firstName, m.lastName, m.gymId, m.status, m.expiresOn,
      normName(m.fullName), m.dateFrom, m.membershipName, m.amountPaid, m.isUpgrade
    );
  }
});

insertAll(members);
db.close();

console.log(`   ✅ Inserted ${members.length} records into SQLite table odoo_members_cache.`);
console.log('✅ Import complete!');
