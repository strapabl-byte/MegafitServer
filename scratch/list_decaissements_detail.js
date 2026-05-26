const lc = require('../localCache');

// Get all decaissements for the last 7 days
const start = '2026-05-18';
const end = '2026-05-24';

const rows = lc.db.prepare(`
  SELECT id, gym_id, date, montant, raison, status, requested_by, approved_by, created_at
  FROM decaissements_cache
  WHERE date >= ? AND date <= ?
  ORDER BY date DESC, created_at DESC
`).all(start, end);

console.log(`Found ${rows.length} decaissements between ${start} and ${end}:`);
console.log(JSON.stringify(rows, null, 2));
