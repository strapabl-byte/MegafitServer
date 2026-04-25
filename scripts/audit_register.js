const db = require('better-sqlite3')('./megafit_cache.db');

const rows = db.prepare(
  "SELECT date, nom, contrat, tpe, espece, virement, cheque, prix FROM register_cache WHERE gym_id='dokarat' AND date LIKE '2026-04%' ORDER BY date"
).all();

console.log('=== DOKARAT APRIL — REVENUE BREAKDOWN ===');
console.log('Total rows:', rows.length);

let totalPaid = 0;
let totalPrix = 0;
const byDate = {};

rows.forEach(r => {
  const paid = Number(r.tpe||0) + Number(r.espece||0) + Number(r.virement||0) + Number(r.cheque||0);
  const prix = Number(r.prix||0);
  totalPaid += paid;
  totalPrix += prix;
  if (!byDate[r.date]) byDate[r.date] = { paid: 0, prix: 0, count: 0 };
  byDate[r.date].paid += paid;
  byDate[r.date].prix += prix;
  byDate[r.date].count++;
});

Object.entries(byDate).sort().forEach(([date, d]) =>
  console.log(date, '→ paid:', d.paid.toLocaleString(), 'DH | prix:', d.prix.toLocaleString(), 'DH | rows:', d.count)
);

console.log('');
console.log('TOTAL PAID  (tpe+espece+virement+cheque):', totalPaid.toLocaleString(), 'DH');
console.log('TOTAL PRIX  (subscription price)        :', totalPrix.toLocaleString(), 'DH');
console.log('KPI endpoint says                       : 751,800 DH');
console.log('Dashboard shows                         : 754,700 DH');
