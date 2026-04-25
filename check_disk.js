const db = require('better-sqlite3')('./megafit_cache.db');
const fs = require('fs');

const fileSize = fs.statSync('./megafit_cache.db').size;
const totalSizeMB = (fileSize / 1024 / 1024).toFixed(2);

const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);

console.log('=== ALL TABLES & ROW COUNTS ===');
let totalRows = 0;
const results = [];
for (const t of tables) {
  try {
    const n = db.prepare(`SELECT COUNT(*) as n FROM "${t}"`).get().n;
    results.push({ table: t, rows: n });
    totalRows += n;
  } catch(e) {}
}
results.sort((a, b) => b.rows - a.rows);
results.forEach(r => console.log(r.table.padEnd(30), r.rows, 'rows'));

console.log('-------------------------------');
console.log('TOTAL ROWS    :', totalRows);
console.log('TOTAL DB SIZE :', totalSizeMB, 'MB');
console.log('Avg bytes/row :', totalRows > 0 ? (fileSize / totalRows).toFixed(0) : 'N/A');

console.log('\n=== GROWTH ESTIMATES PER YEAR (all tables) ===');
const growthItems = [
  { label: 'Door entries      (~400/day, biggest table)', mb: 114 },
  { label: 'Register entries  (~20/day)', mb: 2.1 },
  { label: 'Payments          (~20/day)', mb: 1.4 },
  { label: 'Members           (~50/month)', mb: 0.3 },
  { label: 'Daily stats       (2 gyms x 365)', mb: 0.07 },
  { label: 'Incidents/Courses (negligible)', mb: 0.03 },
];
let totalGrowth = 0;
growthItems.forEach(g => { console.log(g.label, '->', g.mb, 'MB/year'); totalGrowth += g.mb; });
console.log('-------------------------------');
console.log('Total growth/year  :', totalGrowth.toFixed(1), 'MB');
console.log('Disk remaining     :', (1024 - parseFloat(totalSizeMB)).toFixed(0), 'MB');
console.log('Years to fill 1GB  :', ((1024 - parseFloat(totalSizeMB)) / totalGrowth).toFixed(1), 'years 🟢');
