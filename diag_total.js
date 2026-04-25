const db = require('better-sqlite3')('./megafit_cache.db');

// 1. Total brut exact depuis SQLite
const total = db.prepare(`
  SELECT SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as total,
  COUNT(*) as entries
  FROM register_cache
  WHERE gym_id = 'dokarat' AND date LIKE '2026-04%'
`).get();

console.log('=== TOTAL SQLite BRUT (avril dokarat) ===');
console.log(`Total: ${total.total} DH | Entrées: ${total.entries}`);

// 2. Toutes les corrections SYSTEM insérées manuellement
const corrRows = db.prepare(`
  SELECT * FROM register_cache
  WHERE gym_id = 'dokarat' AND date LIKE '2026-04%' AND id LIKE 'CORR_%'
`).all();
console.log('\n=== LIGNES DE CORRECTION SYSTÈME ===');
corrRows.forEach(r => {
  const paid = Number(r.tpe)+Number(r.espece)+Number(r.virement)+Number(r.cheque);
  console.log(`ID: ${r.id} | Date: ${r.date} | Montant: ${paid} DH | Nom: ${r.nom}`);
});

// 3. Par jour avec cumul
const daily = db.prepare(`
  SELECT date,
    COUNT(*) as n,
    SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as rev
  FROM register_cache
  WHERE gym_id = 'dokarat' AND date LIKE '2026-04%'
  GROUP BY date ORDER BY date
`).all();

console.log('\n=== DÉTAIL JOURNALIER ===');
let running = 0;
daily.forEach(d => {
  running += d.rev;
  console.log(`${d.date} | ${d.n} lignes | ${d.rev} DH | Cumul: ${running} DH`);
});
