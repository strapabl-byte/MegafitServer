const db = require('better-sqlite3')('./megafit_cache.db');

// Show ALL April Dokarat entries where reste > 0
const entries = db.prepare(`
  SELECT date, nom, tpe, espece, virement, cheque, prix, reste,
         (CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as paid
  FROM register_cache
  WHERE gym_id='dokarat' AND date LIKE '2026-04%'
  ORDER BY date
`).all();

let totalPaid = 0;
let totalReste = 0;
let entriesWithReste = 0;

entries.forEach(e => {
  totalPaid += Number(e.paid || 0);
  const reste = Number(e.reste || 0);
  if (reste > 0) {
    entriesWithReste++;
    totalReste += reste;
    console.log(`${e.date} | ${e.nom || '?'} | paid: ${e.paid} DH | prix: ${e.prix} DH | RESTE DÛ: ${reste} DH`);
  }
});

console.log('\n=== SUMMARY ===');
console.log('Total rows             :', entries.length);
console.log('Rows with reste > 0    :', entriesWithReste);
console.log('Sum of PAID amounts    :', totalPaid.toLocaleString(), 'DH ← revenue counted');
console.log('Sum of RESTE (owed)    :', totalReste.toLocaleString(), 'DH ← NOT counted ✅');
console.log('Décaissements          :', '2,000 DH');
console.log('NET REVENUE            :', (totalPaid - 2000).toLocaleString(), 'DH');
