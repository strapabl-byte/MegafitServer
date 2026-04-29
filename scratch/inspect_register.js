const db = require('better-sqlite3')('megafit_cache.db');
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
console.log('Tables:', tables.map(t => t.name));

// Find register table
const regTable = tables.find(t => t.name.includes('register'));
if (regTable) {
  const cols = db.prepare(`PRAGMA table_info(${regTable.name})`).all();
  console.log('\n' + regTable.name + ' columns:', cols.map(c => c.name));
  const sample = db.prepare(`SELECT * FROM ${regTable.name} LIMIT 3`).all();
  console.log('Sample:', JSON.stringify(sample[0], null, 2));
}
