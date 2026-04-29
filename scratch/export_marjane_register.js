const lc = require('../localCache');
const fs = require('fs');
const path = require('path');

const rows = lc.db.prepare(`
  SELECT * FROM register_cache 
  WHERE gym_id='marjane' AND date IN ('2026-04-25','2026-04-26','2026-04-27')
  AND id LIKE 'marjane-%'
  ORDER BY date, id
`).all();

console.log(`Found ${rows.length} entries to export.`);
rows.forEach(r => console.log(`  [${r.date}] ${r.nom} — ${r.tpe + r.espece + r.virement + r.cheque} DH`));

const outPath = path.join(__dirname, '..', 'seed_register_marjane_apr2026.json');
fs.writeFileSync(outPath, JSON.stringify(rows, null, 2));
console.log(`\n✅ Exported to seed_register_marjane_apr2026.json`);
