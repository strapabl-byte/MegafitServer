const db = require('better-sqlite3')('./megafit_cache.db');

// Check schema
console.log('=== DECAISSEMENTS_CACHE SCHEMA ===');
console.log(db.prepare("PRAGMA table_info(decaissements_cache)").all().map(c => c.name).join(', '));

// All rows
const rows = db.prepare("SELECT * FROM decaissements_cache WHERE gym_id='dokarat'").all();
console.log('\nTotal dokarat décaissements in SQLite:', rows.length);

let total = 0;
rows.forEach(r => {
  console.log(r.date, '→', r.montant, 'DH |', r.raison || r.reason || JSON.stringify(r));
  total += Number(r.montant || 0);
});
console.log('TOTAL subtracted:', total, 'DH');
console.log('Expected subtraction: 18,000 DH');
console.log('Missing:', 18000 - total, 'DH');
