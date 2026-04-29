const fs = require('fs');
const Database = require('better-sqlite3');
const db = new Database('megafit_cache.db');

const entries = db.prepare(`SELECT * FROM entries WHERE gym_id='dokarat' AND date <= '2026-04-27'`).all();
fs.writeFileSync('seed_entries.json', JSON.stringify(entries));
console.log('Exported', entries.length, 'entries to seed_entries.json');
