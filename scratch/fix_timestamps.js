const lc = require('../localCache');
const db = lc.db;

console.log('Normalizing timestamps in SQLite...');

const tFix = db.prepare("UPDATE entries SET timestamp = REPLACE(timestamp, 'T', ' ') WHERE timestamp LIKE '%T%'").run();
console.log(`✅ Replaced 'T' in ${tFix.changes} rows.`);

const zFix = db.prepare("UPDATE entries SET timestamp = REPLACE(timestamp, 'Z', '') WHERE timestamp LIKE '%Z%'").run();
console.log(`✅ Removed 'Z' in ${zFix.changes} rows.`);

console.log('Done!');
