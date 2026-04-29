const Database = require('better-sqlite3');
const db = new Database('megafit_cache.db');
console.table(db.prepare("SELECT date, count, raw_count FROM daily_stats WHERE gym_id='dokarat' AND date >= '2026-04-18'").all());
