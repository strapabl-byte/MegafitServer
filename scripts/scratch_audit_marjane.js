const lc = require('./localCache');
const target = '2026-04';
const gymIds = ['marjane'];
const placeholders = '?';

// Query without ANY exclusion filters
const rowsAll = lc.db.prepare(`
        SELECT
          commercial,
          COUNT(*)                 AS count,
          SUM(prix)                AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
        GROUP BY UPPER(TRIM(commercial))
        ORDER BY revenue DESC
`).all(...gymIds, `${target}%`);

console.log('--- RAW ALL ENTRIES (MARJANE) ---');
console.log(JSON.stringify(rowsAll, null, 2));

const sumRaw = rowsAll.reduce((s, r) => s + r.revenue, 0);
console.log(`\nTOTAL RAW REVENUE: ${sumRaw}`);

// The exact filter we use in commercials:
const rowsFiltered = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial))  AS commercial,
          SUM(prix)                AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
          AND commercial IS NOT NULL
          AND TRIM(commercial) != ''
          AND TRIM(commercial) != '-'
          AND UPPER(TRIM(commercial)) NOT LIKE '%@%'
          AND UPPER(TRIM(commercial)) NOT LIKE 'MR%'
          AND UPPER(TRIM(commercial)) NOT IN ('OFFERT','GRATUIT','TEST','SYSTEM')
        GROUP BY UPPER(TRIM(commercial))
        ORDER BY revenue DESC
`).all(...gymIds, `${target}%`);

const sumFiltered = rowsFiltered.reduce((s, r) => s + r.revenue, 0);
console.log(`\nTOTAL CHALLENGE REVENUE: ${sumFiltered}`);

console.log(`\nDIFFERENCE: ${sumRaw - sumFiltered} DH`);
