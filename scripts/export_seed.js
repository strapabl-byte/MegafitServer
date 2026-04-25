const db = require('better-sqlite3')('./megafit_cache.db');
const fs = require('fs');

const daily_stats = db.prepare(
  "SELECT gym_id, date, count, raw_count FROM daily_stats WHERE gym_id IN ('dokarat','marjane') ORDER BY date DESC"
).all();

fs.writeFileSync('./seed_export.json', JSON.stringify({ daily_stats }, null, 2));
console.log('✅ Exported', daily_stats.length, 'daily_stats rows to seed_export.json');
daily_stats.slice(0, 5).forEach(r => console.log(' -', r.gym_id, r.date, 'unique:', r.count));
