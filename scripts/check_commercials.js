const lc = require('./localCache');
const rows = lc.db.prepare(`
  SELECT
    UPPER(TRIM(commercial)) AS commercial,
    COUNT(*) as cnt,
    SUM(prix) as rev
  FROM register_cache
  WHERE gym_id='dokarat'
    AND date LIKE '2026-04%'
    AND commercial IS NOT NULL
    AND TRIM(commercial) != ''
    AND UPPER(TRIM(commercial)) NOT LIKE '%@%'
    AND UPPER(TRIM(commercial)) NOT LIKE 'MR%'
    AND UPPER(TRIM(commercial)) NOT IN ('OFFERT','GRATUIT','TEST','SYSTEM')
  GROUP BY UPPER(TRIM(commercial))
  ORDER BY rev DESC
`).all();
console.log(JSON.stringify(rows, null, 2));
console.log('\nTotal CA:', rows.reduce((s,r)=>s+r.rev,0).toLocaleString(), 'DH');
console.log('Total inscriptions:', rows.reduce((s,r)=>s+r.cnt,0));
