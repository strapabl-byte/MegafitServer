const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log("📊 UPDATING DAILY STATS FROM RAW ENTRIES...");

const rows = db.prepare(`
  SELECT date, COUNT(*) as total_entries, COUNT(DISTINCT name) as unique_people
  FROM entries 
  WHERE gym_id = 'dokarat'
  GROUP BY date 
  ORDER BY date ASC
`).all();

const updateStmt = db.prepare(`
  INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count, synced_at)
  VALUES ('dokarat', ?, ?, ?, ?)
`);

db.transaction(() => {
  for (const row of rows) {
    const now = new Date().toISOString();
    updateStmt.run(row.date, row.unique_people, row.total_entries, now);
    console.log(`✅ Updated ${row.date}: Uniques = ${row.unique_people}, Raw = ${row.total_entries}`);
  }
})();

console.log("🎉 ALL DAILY STATS HARDCODED/UPDATED FROM ENTRIES!");
