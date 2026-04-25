const lc = require('./localCache');
const target = '2026-04';
const gymIds = ['dokarat'];
const placeholders = '?';
const rows = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial))  AS commercial,
          gym_id,
          COUNT(*)                 AS inscriptions,
          SUM(prix)                AS revenue,
          MIN(date)                AS first_sale,
          MAX(date)                AS last_sale
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
          AND commercial IS NOT NULL
          AND TRIM(commercial) != ''
          AND UPPER(TRIM(commercial)) NOT LIKE '%@%'
          AND UPPER(TRIM(commercial)) NOT LIKE 'MR%'
          AND UPPER(TRIM(commercial)) NOT IN ('OFFERT','GRATUIT','TEST','SYSTEM','REDA','SABER')
        GROUP BY UPPER(TRIM(commercial)), gym_id
        ORDER BY revenue DESC
`).all(...gymIds, `${target}%`);
console.log(rows);
