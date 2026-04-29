// Force-load Odoo members into local SQLite right now
require('dotenv').config();
const path = require('path');
const fs   = require('fs');
const lc   = require('../localCache');

const slimPath = path.join(__dirname, '../data/odoo_members_slim.json');
const members  = JSON.parse(fs.readFileSync(slimPath, 'utf8'));
const normName = s => (s || '').replace(/\s+/g, ' ').trim().toUpperCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

// Clear and reload
lc.db.prepare('DELETE FROM odoo_members_cache').run();
const insert = lc.db.prepare(`
  INSERT OR IGNORE INTO odoo_members_cache (full_name, first_name, last_name, gym_id, status, expires_on, name_norm)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const tx = lc.db.transaction(rows => { for (const m of rows) insert.run(m.fullName, m.firstName, m.lastName, m.gymId, m.status, m.expiresOn, normName(m.fullName)); });
tx(members);

const marjane = lc.db.prepare("SELECT COUNT(*) as c FROM odoo_members_cache WHERE gym_id='marjane'").get().c;
const dokarat = lc.db.prepare("SELECT COUNT(*) as c FROM odoo_members_cache WHERE gym_id='dokarat'").get().c;
console.log(`✅ Loaded ${members.length} total members`);
console.log(`   Marjane : ${marjane}`);
console.log(`   Dokarat : ${dokarat}`);

// Quick test: search for meskine youness
const test = lc.db.prepare("SELECT * FROM odoo_members_cache WHERE name_norm LIKE '%MESKINE%' LIMIT 3").all();
console.log('\n🔍 Test search "MESKINE":', test.map(m => `${m.full_name} (${m.gym_id}, ${m.status})`));
process.exit(0);
