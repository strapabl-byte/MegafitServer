const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('--- DATABASE DIAGNOSTICS ---');

const minMax = db.prepare(`SELECT MIN(date) as minD, MAX(date) as maxD, COUNT(*) as count FROM register_cache`).get();
console.log(`register_cache bounds: Min=${minMax.minD}, Max=${minMax.maxD}, Total Rows=${minMax.count}`);

// Let's print all monthly revenues per gym
console.log('\n--- Monthly Gross Revenue per Gym ---');
const monthlyStats = db.prepare(`
  SELECT 
    gym_id, 
    substr(date, 1, 7) as month, 
    SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as revenue,
    COUNT(*) as count
  FROM register_cache
  GROUP BY gym_id, month
  ORDER BY month DESC, gym_id ASC
`).all();
console.log(monthlyStats);

// Let's search for the exact values in the daily_stats table or register_cache
console.log('\n--- Searching for close numbers ---');
const searchNum = (val) => {
  const match = db.prepare(`
    SELECT date, gym_id, SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as total
    FROM register_cache
    GROUP BY date, gym_id
    HAVING ABS(total - ?) < 1000
  `).all(val);
  return match;
};
console.log('Close to 88733 daily:', searchNum(88733));
console.log('Close to 93755 daily:', searchNum(93755));
