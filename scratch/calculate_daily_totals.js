const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log("📊 CALCULATING DAILY TOTALS FROM LOCAL SQLITE LOGS...");

const rows = db.prepare(`
  SELECT date, COUNT(*) as total_entries, COUNT(DISTINCT name) as unique_people
  FROM entries 
  WHERE gym_id = 'dokarat'
  GROUP BY date 
  ORDER BY date ASC
`).all();

console.log("\n📅 DATE       | 🚪 TOTAL SCANS | 👤 UNIQUE PEOPLE");
console.log("-------------------------------------------------");
let grandTotal = 0;
let grandUnique = 0;

for (const row of rows) {
  console.log(`${row.date}   | ${String(row.total_entries).padStart(13, ' ')} | ${String(row.unique_people).padStart(15, ' ')}`);
  grandTotal += row.total_entries;
  grandUnique += row.unique_people; // Note: sum of daily uniques isn't true grand unique, just sum of daily distincts
}

console.log("-------------------------------------------------");
console.log(`TOTALS       | ${String(grandTotal).padStart(13, ' ')} | ${String(grandUnique).padStart(15, ' ')} (Sum of daily uniques)`);
