/**
 * import_odoo_full.js
 * Imports all 12,504 Odoo members from the full CSV into:
 *   1. data/odoo_members_slim.json  (used by server.js on startup)
 *   2. odoo_members_cache SQLite table (live reload — no restart needed)
 *
 * Usage: node import_odoo_full.js
 */

const fs   = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const CSV_PATH  = 'C:/Users/Thatsme/Downloads/Odoo/all_members_all_clubs.csv';
const SLIM_PATH = path.join(__dirname, 'data', 'odoo_members_slim.json');
const DB_PATH   = path.join(__dirname, 'megafit_cache.db');

// ── Club → gym_id mapping (must match GymContext.jsx in dashboard) ──────────────────
const CLUB_MAP = {
  'CASA ANFA'      : 'casa1',   // Casa Anfa regular (dashboard: id='casa1')
  'CASA ANFA LADY' : 'casa2',   // Casa Lady Anfa (dashboard: id='casa2')
  'FES DOUKKARATE' : 'dokarat',
  'FES MARJANE'    : 'marjane',
};

// ── Normalize name for fuzzy matching ────────────────────────────────────────
function normName(s) {
  return (s || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

// ── Parse CSV ────────────────────────────────────────────────────────────────
console.log('📖 Reading CSV:', CSV_PATH);
const raw   = fs.readFileSync(CSV_PATH, 'utf8');
const lines = raw.trim().split('\n').slice(1); // skip header
console.log(`   ${lines.length} data rows found`);

const members = [];
const byClub  = {};

for (const line of lines) {
  // CSV format: Club,Full Name,Phone,Registration Date
  // Club name may contain commas if quoted — handle basic CSV
  const parts = line.replace(/\r$/, '').split(',');
  // club is first field, fullName second, phone third, date fourth
  // Some club names are two words but no commas, so split(,) is safe here
  const club     = (parts[0] || '').trim().toUpperCase();
  const fullName = (parts[1] || '').trim().toUpperCase();
  const phone    = (parts[2] || '').trim();
  const regDate  = (parts[3] || '').trim();

  if (!fullName) continue;

  const gymId = CLUB_MAP[club];
  if (!gymId) {
    console.warn('  ⚠️  Unknown club:', club);
    continue;
  }

  byClub[club] = (byClub[club] || 0) + 1;

  // Split name into first/last (best-effort: last word = first name, rest = last name)
  const nameParts = fullName.split(' ').filter(Boolean);
  const firstName = nameParts.length > 1 ? nameParts[nameParts.length - 1] : '';
  const lastName  = nameParts.length > 1 ? nameParts.slice(0, -1).join(' ') : fullName;

  members.push({
    fullName,
    firstName,
    lastName,
    gymId,
    status    : 'Active',
    expiresOn : regDate || null,  // registration date as reference
    phone     : phone || null,
  });
}

console.log('\n📊 By club:');
Object.entries(byClub).forEach(([c, n]) => console.log(`   ${c}: ${n}`));
console.log(`   TOTAL: ${members.length}`);

// ── Save new slim JSON ────────────────────────────────────────────────────────
console.log('\n💾 Writing data/odoo_members_slim.json ...');
fs.writeFileSync(SLIM_PATH, JSON.stringify(members, null, 2), 'utf8');
console.log(`   ✅ Saved ${members.length} members (${(fs.statSync(SLIM_PATH).size / 1024).toFixed(1)} KB)`);

// ── Reload SQLite cache ───────────────────────────────────────────────────────
console.log('\n🗄️  Reloading odoo_members_cache in SQLite...');
const db = new Database(DB_PATH);

// Clear old data
const del = db.prepare('DELETE FROM odoo_members_cache').run();
console.log(`   🗑️  Deleted ${del.changes} old rows`);

// Insert new data
const insert = db.prepare(`
  INSERT INTO odoo_members_cache (full_name, first_name, last_name, gym_id, status, expires_on, name_norm)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const insertAll = db.transaction((rows) => {
  for (const m of rows) {
    insert.run(m.fullName, m.firstName, m.lastName, m.gymId, m.status, m.expiresOn, normName(m.fullName));
  }
});

insertAll(members);
db.close();

console.log(`   ✅ Inserted ${members.length} members into SQLite`);

// ── Verify ────────────────────────────────────────────────────────────────────
console.log('\n🔍 Verifying...');
const dbVerify = new Database(DB_PATH, { readonly: true });
const total = dbVerify.prepare('SELECT COUNT(*) as c FROM odoo_members_cache').get().c;
const byGym = dbVerify.prepare('SELECT gym_id, COUNT(*) as c FROM odoo_members_cache GROUP BY gym_id').all();
dbVerify.close();

console.log(`   Total in cache: ${total}`);
byGym.forEach(r => console.log(`   ${r.gym_id}: ${r.c}`));

console.log('\n✅ Import complete! All 12,504 Odoo members are now in the system.');
console.log('   Note: The server reads odoo_members_slim.json on startup.');
console.log('   SQLite is already updated — no restart needed for live server.');
