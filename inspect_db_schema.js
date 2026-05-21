const Database = require('better-sqlite3');
const db = new Database('megafit_cache.db');

const tableInfo = db.prepare("PRAGMA table_info(register_cache)").all();
console.log('Columns in register_cache:');
tableInfo.forEach(col => {
  console.log(`- ${col.name} (${col.type})`);
});
