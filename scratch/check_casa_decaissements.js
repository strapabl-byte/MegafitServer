const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('--- ALL DECAISSEMENTS FOR CASA ANFA (CASA1) IN MAY 2026 ---');
const rows = db.prepare(`
  SELECT date, montant, raison, status, requested_by, approved_by
  FROM decaissements_cache
  WHERE gym_id = 'casa1' AND date >= '2026-05-01'
  ORDER BY date DESC
`).all();

let total = 0;
let totalApproved = 0;
let totalPending = 0;

rows.forEach(r => {
  console.log(`Date: ${r.date} | Montant: ${r.montant} DH | Reason: ${r.raison.trim()} | Status: ${r.status}`);
  total += Number(r.montant);
  if (r.status === 'approved' || r.status === '' || r.status === null) {
    totalApproved += Number(r.montant);
  } else if (r.status === 'pending') {
    totalPending += Number(r.montant);
  }
});

console.log('\nSummary:');
console.log('Total Decaissements:', total);
console.log('Total Approved/Default Decaissements:', totalApproved);
console.log('Total Pending Decaissements:', totalPending);
