// scripts/export_daily_stats.js
// Exports the local SQLite daily_stats to a JSON seed file
// Run: node scripts/export_daily_stats.js

const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '..', 'megafit_cache.db');
const OUT_PATH = path.join(__dirname, '..', 'seed_daily_stats.json');

const db = new Database(DB_PATH, { readonly: true });

const rows = db.prepare(`
  SELECT gym_id, date, count, raw_count
  FROM daily_stats
  WHERE count > 0
  ORDER BY gym_id, date
`).all();

db.close();

fs.writeFileSync(OUT_PATH, JSON.stringify(rows, null, 2));
console.log(`✅ Exported ${rows.length} daily_stats rows to seed_daily_stats.json`);
rows.forEach(r => console.log(`  ${r.gym_id} / ${r.date}: ${r.count} unique`));
