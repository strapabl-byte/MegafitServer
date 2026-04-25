const db = require('better-sqlite3')('./megafit_cache.db');

// Les jours problématiques : 18 (extra 12,800) et 20 (extra 4,900)
['2026-04-18', '2026-04-20'].forEach(date => {
  const rows = db.prepare(`
    SELECT id, nom, 
      CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC) as paid
    FROM register_cache
    WHERE gym_id='dokarat' AND date=?
    ORDER BY paid DESC
  `).all(date);
  
  const total = rows.reduce((s, r) => s + r.paid, 0);
  console.log(`\n=== ${date} | Total: ${total} DH ===`);
  rows.forEach(r => console.log(`  ID: ${r.id} | ${String(r.nom).padEnd(30)} | ${r.paid} DH`));
});
