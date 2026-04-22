// dump_local_cache.js
// Reads the existing SQLite cache and saves everything to JSON files
// NO Firebase calls — 100% local, zero quota cost
// Run with: node dump_local_cache.js

'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

const DB_PATH  = path.join(__dirname, 'megafit_cache.db');
const OUT_DIR  = path.join(__dirname, '..', 'megafit-local-backup');

if (!fs.existsSync(DB_PATH)) {
  console.error('❌ No SQLite cache found at:', DB_PATH);
  process.exit(1);
}

fs.mkdirSync(OUT_DIR, { recursive: true });

const db = new Database(DB_PATH, { readonly: true });

function dump(tableName, filename, label) {
  try {
    const rows = db.prepare(`SELECT * FROM ${tableName}`).all();
    const outPath = path.join(OUT_DIR, filename);
    fs.writeFileSync(outPath, JSON.stringify(rows, null, 2), 'utf8');
    console.log(`✅ [${label}] ${rows.length} rows → ${outPath}`);
    return rows.length;
  } catch (err) {
    console.warn(`⚠️  Could not dump ${tableName}:`, err.message);
    return 0;
  }
}

console.log('\n📦 Dumping MegaFit local SQLite cache to JSON files...\n');
console.log(`   Source  : ${DB_PATH}`);
console.log(`   Output  : ${OUT_DIR}\n`);

const stats = {
  members:  dump('members_cache',  'members.json',       'Members'),
  register: dump('register_cache', 'register.json',      'Register / Payments'),
  entries:  dump('entries',        'door_entries.json',  'Door Entries'),
  stats:    dump('daily_stats',    'daily_stats.json',   'Daily Stats'),
  payments: dump('payments_cache', 'payments.json',      'Payments Cache'),
  meta:     dump('meta',           'meta.json',          'Meta / Sync Timestamps'),
};

const total = Object.values(stats).reduce((a, b) => a + b, 0);

console.log(`\n📊 Summary:`);
Object.entries(stats).forEach(([k, v]) => console.log(`   ${k.padEnd(12)} ${v} rows`));
console.log(`   ${'TOTAL'.padEnd(12)} ${total} rows`);
console.log(`\n✨ Done. All data saved to: ${OUT_DIR}\n`);
console.log(`ℹ️  No Firebase reads were made. Zero quota cost.`);
