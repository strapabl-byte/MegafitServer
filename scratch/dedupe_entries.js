const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log("🧹 DEDUPLICATING OVERLAPPING ENTRIES (WITH 3H WINDOW)...");

const overlapDates = db.prepare(`
  SELECT date 
  FROM entries 
  WHERE gym_id='dokarat' AND date >= '2026-04-18' 
  GROUP BY date
`).all().map(r => r.date);

let deletedCount = 0;

db.transaction(() => {
  for (const date of overlapDates) {
    const liveEntries = db.prepare(`SELECT * FROM entries WHERE gym_id='dokarat' AND date=? AND id NOT LIKE 'dokarat_%'`).all(date);
    const importedEntries = db.prepare(`SELECT * FROM entries WHERE gym_id='dokarat' AND date=? AND id LIKE 'dokarat_%'`).all(date);

    for (const imp of importedEntries) {
      const impTime = new Date(imp.timestamp).getTime();
      const impName = imp.name.toLowerCase().replace(/\s/g, '');

      // Look for a live entry within 3 hours (to account for timezone mismatch) with a similar name
      const duplicate = liveEntries.find(live => {
        const liveTime = new Date(live.timestamp).getTime();
        const liveName = live.name.toLowerCase().replace(/\s/g, '');
        const timeDiff = Math.abs(impTime - liveTime);
        
        return timeDiff <= (3 * 3600000 + 120000) && (impName.includes(liveName) || liveName.includes(impName));
      });

      if (duplicate) {
        db.prepare(`DELETE FROM entries WHERE id=?`).run(imp.id);
        deletedCount++;
      }
    }
  }
})();

console.log(`✅ Deduplication complete! Deleted ${deletedCount} overlapping imported entries.`);
