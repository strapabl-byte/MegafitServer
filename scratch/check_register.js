const db = require('better-sqlite3')('./megafit_cache.db');

// Sample 5 rows for marjane this month
const rows = db.prepare(
  "SELECT gym_id, date, nom, prix, tpe, espece, virement, cheque FROM register_cache WHERE gym_id='marjane' AND date>='2026-04-01' ORDER BY date LIMIT 5"
).all();
console.log('--- SAMPLE ROWS (marjane, April) ---');
console.table(rows);

// Totals for marjane this month
const totals = db.prepare(
  "SELECT gym_id, COUNT(*) as entries, SUM(prix) as sum_prix, SUM(tpe) as sum_tpe, SUM(espece) as sum_espece, SUM(virement) as sum_virement, SUM(cheque) as sum_cheque, SUM(tpe+espece+virement+cheque) as sum_real FROM register_cache WHERE gym_id='marjane' AND date>='2026-04-01'"
).get();
console.log('\n--- TOTALS (marjane, April 2026) ---');
console.log(totals);
