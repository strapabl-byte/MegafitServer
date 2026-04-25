const db = require('better-sqlite3')('./megafit_cache.db');

// Total réel : uniquement TPE + Espece + Virement + Chèque — JAMAIS le reste
// On exclut aussi les lignes CORR_ qui sont des corrections manuelles artificielles
const result = db.prepare(`
  SELECT 
    SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as total,
    COUNT(*) as n
  FROM register_cache
  WHERE gym_id = 'dokarat' 
    AND date LIKE '2026-04%'
    AND id NOT LIKE 'CORR_%'
`).get();

console.log('=== TOTAL RÉEL REGISTRE DOKARAT (Avril 2026) ===');
console.log('Total encaissé (TPE+Especes+Virement+Cheque) :', result.total, 'DH');
console.log('Nombre d\'entrées :', result.n);

// Aussi avec les CORR_ pour voir leur impact
const withCorr = db.prepare(`
  SELECT 
    SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as total,
    COUNT(*) as n
  FROM register_cache
  WHERE gym_id = 'dokarat' AND date LIKE '2026-04%'
`).get();

console.log('\nAvec lignes CORR_ incluses :', withCorr.total, 'DH (' + withCorr.n + ' entrées)');
console.log('Impact des CORR_ :', (withCorr.total - result.total), 'DH');
