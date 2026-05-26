const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('--- ALL TABLES AND ROW COUNTS ---');
const tables = db.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all();
tables.forEach(t => {
  const cnt = db.prepare(`SELECT COUNT(*) as count FROM "${t.name}"`).get();
  console.log(`Table: ${t.name} | Rows: ${cnt.count}`);
});

console.log('\n--- SAMPLE FROM DAILY_STATS ---');
try {
  const sampleDS = db.prepare(`SELECT * FROM daily_stats ORDER BY date DESC LIMIT 5`).all();
  console.log(sampleDS);
} catch (e) {
  console.log('No daily_stats or error:', e.message);
}

console.log('\n--- SAMPLE FROM DECAISSEMENTS ---');
try {
  const sampleDec = db.prepare(`SELECT * FROM decaissements_cache ORDER BY date DESC LIMIT 5`).all();
  console.log(sampleDec);
} catch (e) {
  console.log('No decaissements_cache or error:', e.message);
}
