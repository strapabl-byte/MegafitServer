const db = require('better-sqlite3')('./megafit_cache.db');

const dates = ['2026-04-01', '2026-04-03', '2026-04-10', '2026-04-15', '2026-04-18', '2026-04-19'];

console.log('=== DÉTAILS DES JOURS À CORRIGER ===');

dates.forEach(d => {
  const rows = db.prepare("SELECT id, nom, tpe, espece, virement, cheque, (CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total FROM register_cache WHERE gym_id='dokarat' AND date = ?").all(d);
  console.log(`\nDATE : ${d} (Total actuel SQLite: ${rows.reduce((sum, r) => sum + r.total, 0)} DH)`);
  rows.forEach(r => {
    console.log(`  ID: ${String(r.id).padEnd(25)} | Nom: ${String(r.nom).padEnd(20)} | Total: ${r.total} DH`);
  });
});
