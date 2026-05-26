const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('--- ALL DECAISSEMENTS (WEEK OF 2026-05-13 to 2026-05-19) ---');
const rows = db.prepare(`
  SELECT gym_id, date, montant, raison, status, requested_by, approved_by
  FROM decaissements_cache
  WHERE date >= '2026-05-13' AND date <= '2026-05-19'
  ORDER BY date ASC, gym_id ASC
`).all();

rows.forEach(r => {
  console.log(`[${r.gym_id.toUpperCase()}] Date: ${r.date} | Montant: ${r.montant} DH | Reason: ${r.raison.trim()} | Status: ${r.status}`);
});
