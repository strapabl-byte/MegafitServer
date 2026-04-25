const lc = require('./localCache');
const target = '2026-04';
const gymIds = ['marjane'];
const placeholders = '?';

const rows = lc.db.prepare(`
        SELECT
          prix,
          tpe, espece, virement, cheque
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
`).all(...gymIds, `${target}%`);

let sumPrix = 0;
let sumPaid = 0;

rows.forEach(r => {
  sumPrix += Number(r.prix) || 0;
  const paid = (Number(r.tpe)||0) + (Number(r.espece)||0) + (Number(r.virement)||0) + (Number(r.cheque)||0);
  sumPaid += paid;
});

console.log(`PRIX TOTAL (Commercial Leaderboard metric): ${sumPrix}`);
console.log(`PAID TOTAL (Heatmap metric): ${sumPaid}`);
