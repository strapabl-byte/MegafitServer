const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

const LOGS_DIR = 'c:/Users/Thatsme/Documents/MegaSolution/entrees';
const GYM_ID = 'dokarat';

db.transaction(() => {
  console.log(`🧹 Wiping all dokarat entries...`);
  // We wipe everything for Dokarat so we can trust the .log files as the ONLY source of truth up to 2026-04-27
  // We'll only wipe dates that exist in the log files to be safe, or just everything up to 2026-04-27
  db.prepare(`DELETE FROM entries WHERE gym_id = ? AND date <= '2026-04-27'`).run(GYM_ID);

  const files = fs.readdirSync(LOGS_DIR).filter(f => f.endsWith('.log'));
  console.log(`Found ${files.length} log files.`);

  const insertStmt = db.prepare(`
    INSERT INTO entries (id, gym_id, date, timestamp, name, method, status, is_face)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let totalImported = 0;
  let rawCounts = {};
  let uniqueCounts = {};

  for (const file of files) {
    const filePath = path.join(LOGS_DIR, file);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const dateStrMatch = file.match(/^(\d{4}-\d{2}-\d{2})/);
    const fileDate = dateStrMatch ? dateStrMatch[1] : null;
    
    let fileRaw = 0;
    const names = new Set();

    for (let line of lines) {
      line = line.trim();
      if (!line) continue;
      
      const match = line.match(/^\[(.*?)\]\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*)$/);
      if (match) {
        const timestampRaw = match[1]; // e.g., 2026-04-26 18:28:23
        const timestamp = timestampRaw.replace(' ', 'T') + 'Z';
        const date = timestampRaw.substring(0, 10);
        const name = match[2].trim();
        const status = match[3].trim();
        const method = match[4].trim();
        
        insertStmt.run(
          `${GYM_ID}_${timestampRaw.replace(/\D/g, '')}_${name.replace(/\s/g, '_')}`, // Make ID unique per line
          GYM_ID,
          date,
          timestamp,
          name,
          method,
          status,
          method.toLowerCase().includes('visage') ? 1 : 0
        );

        fileRaw++;
        names.add(name.toLowerCase());
        
        if (!rawCounts[date]) { rawCounts[date] = 0; uniqueCounts[date] = new Set(); }
        rawCounts[date]++;
        uniqueCounts[date].add(name.toLowerCase());
      }
    }

    if (fileRaw > 0) {
      totalImported += fileRaw;
      console.log(`✅ Imported exactly ${fileRaw} entries from ${file}`);
    }
  }

  console.log(`\n🎉 Import complete! Total entries inserted: ${totalImported}`);

  // Now overwrite daily_stats for Dokarat based STRICTLY on the files
  console.log(`\n📊 Updating daily_stats...`);
  const updateStatStmt = db.prepare(`
    INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count, synced_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (const date of Object.keys(rawCounts)) {
    const raw = rawCounts[date];
    const unique = uniqueCounts[date].size;
    updateStatStmt.run(GYM_ID, date, unique, raw, new Date().toISOString());
    console.log(`   -> ${date}: ${raw} bruts, ${unique} uniques`);
  }

})();

