const lc = require('./localCache');
const sum23 = lc.db.prepare(`
  SELECT SUM(tpe+espece+virement+cheque) as paid
  FROM register_cache
  WHERE gym_id='marjane' AND date='2026-04-23'
`).get();

const sumOther = lc.db.prepare(`
  SELECT SUM(tpe+espece+virement+cheque) as paid
  FROM register_cache
  WHERE gym_id='marjane' AND date LIKE '2026-04%' AND date != '2026-04-23'
`).get();

console.log("Date 23:", sum23.paid);
console.log("Other dates:", sumOther.paid);
