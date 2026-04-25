const lc = require('./localCache');
const target = '2026-04';
const gymIds = ['marjane'];
const placeholders = '?';
const rows = lc.db.prepare(`
        SELECT
          commercial,
          COUNT(*)                 AS inscriptions,
          SUM(prix)                AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
        GROUP BY commercial
        ORDER BY revenue DESC
`).all(...gymIds, `${target}%`);
console.log(JSON.stringify(rows, null, 2));

const totalRev = rows.reduce((s, r) => s + r.revenue, 0);
console.log(`\nTotal Fes Saiss CA: ${totalRev} DH`);
