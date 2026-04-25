const db = require('better-sqlite3')('./megafit_cache.db');

const rows = db.prepare(`
  SELECT 
    date,
    SUM(CAST(tpe AS NUMERIC)) as tpe,
    SUM(CAST(espece AS NUMERIC)) as espece,
    SUM(CAST(virement AS NUMERIC)) as virement,
    SUM(CAST(cheque AS NUMERIC)) as cheque,
    COUNT(*) as entries
  FROM register_cache
  WHERE gym_id = 'dokarat' AND date LIKE '2026-04%'
  GROUP BY date
  ORDER BY date ASC
`).all();

console.log('=== CA JOURNÉE DOKARAT - AVRIL 2026 ===');
console.log('------------------------------------------------------------');
console.log('Date       | Entrées | Brut (Paiements) | Déc. | CA NET');
console.log('------------------------------------------------------------');

let grandTotalBrut = 0;
let grandTotalNet = 0;

rows.forEach(r => {
  const brut = Number(r.tpe) + Number(r.espece) + Number(r.virement) + Number(r.cheque);
  
  // Fetch decs for this day
  const decs = db.prepare("SELECT SUM(CAST(montant AS NUMERIC)) as total FROM decaissements_cache WHERE gym_id='dokarat' AND date = ?").get(r.date);
  const decAmt = Number(decs.total || 0);
  const net = brut - decAmt;

  grandTotalBrut += brut;
  grandTotalNet += net;

  console.log(`${r.date} | ${String(r.entries).padEnd(7)} | ${brut.toLocaleString().padEnd(16)} | ${decAmt.toLocaleString().padEnd(4)} | ${net.toLocaleString()} DH`);
});

console.log('------------------------------------------------------------');
console.log(`TOTAL MOIS |         | ${grandTotalBrut.toLocaleString().padEnd(16)} |      | ${grandTotalNet.toLocaleString()} DH`);
