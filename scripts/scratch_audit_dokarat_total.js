const lc = require('./localCache');
const target = '2026-04';
const gymIds = ['dokarat'];
const placeholders = '?';

const total = lc.db.prepare(`
        SELECT
          COUNT(*)                 AS count,
          SUM(prix)                AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
`).get(...gymIds, `${target}%`);

console.log('--- ABSOLUTE TOTAL DOKARAT (NO GROUPING) ---');
console.log(total);
