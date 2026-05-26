const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('--- ALL APPROVED DECAISSEMENTS FOR DOKARAT ---');
const decs = db.prepare(`
  SELECT id, date, montant, raison, status, requested_by, approved_by
  FROM decaissements_cache
  WHERE gym_id = 'dokarat' AND (status = 'approved' OR status IS NULL OR status = '')
  ORDER BY date DESC
`).all();

let total = 0;
decs.forEach(d => {
  console.log(`Date: ${d.date} | Montant: ${d.montant} | Reason: ${d.raison.trim()} | Status: ${d.status}`);
  total += Number(d.montant);
});
console.log('Total Approved Decaissements:', total);
