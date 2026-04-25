const db = require('better-sqlite3')('./megafit_cache.db');
const expected = [
  39600, 55600, 45500, 44550, 4500, 14300, 38900, 29000, 38900, 46450, 
  24800, 30500, 18000, 42100, 17550, 9100, 55100, 53900, 6300, 34700, 
  42900, 24050, 20700, 18700
];

let total = 0;
console.log('--- Audit Dokarat Avril ---');
for (let i = 1; i <= 24; i++) {
  const date = `2026-04-${String(i).padStart(2, '0')}`;
  const r = db.prepare(`
    SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as t 
    FROM register_cache WHERE gym_id='dokarat' AND date=?
  `).get(date);
  
  const got = r.t || 0;
  const exp = expected[i - 1];
  
  if (got !== exp) {
    console.log(`❌ ${date}: Reçu ${got.toLocaleString()} DH | Attendu ${exp.toLocaleString()} DH | Écart ${got - exp} DH`);
  }
  total += got;
}
console.log(`\nTOTAL LOCAL : ${total.toLocaleString()} DH`);
console.log(`Cible Excel : 755,700 DH`);
console.log(`Écart       : ${total - 755700} DH`);
