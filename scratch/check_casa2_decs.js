const lc = require('../localCache');
const start = '2026-05-18';
const end = '2026-05-24';

const rows = lc.db.prepare(`
  SELECT id, date, montant, raison, status, requested_by, created_at
  FROM decaissements_cache
  WHERE gym_id = 'casa2' AND date >= ? AND date <= ?
  ORDER BY date DESC
`).all(start, end);

console.log('Lady Anfa Decaissements detail:');
console.table(rows);
