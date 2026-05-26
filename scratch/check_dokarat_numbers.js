const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
console.log('Connecting to database:', dbPath);
const db = new Database(dbPath);

// Current date
const todayStr = '2026-05-24';
const monthStart = '2026-05-01';

// Week start (7 days ago: today - 6 days = 2026-05-18)
const weekStart = '2026-05-18';

// Query for Dokarat Month (2026-05-01 to 2026-05-24)
const getStats = (gymId, start, end) => {
  // Gross Revenue from register_cache
  const revRow = db.prepare(`
    SELECT COALESCE(SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)), 0) AS total
    FROM register_cache 
    WHERE gym_id = ? AND date >= ? AND date <= ?
  `).get(gymId, start, end);

  // Decaissements
  const decRow = db.prepare(`
    SELECT COALESCE(SUM(CAST(montant AS NUMERIC)), 0) AS total
    FROM decaissements_cache
    WHERE gym_id = ? AND date >= ? AND date <= ? AND (status = 'approved' OR status IS NULL OR status = '')
  `).get(gymId, start, end);

  return {
    gross: Math.round(revRow.total),
    decaissements: Math.round(decRow.total),
    net: Math.round(revRow.total - decRow.total)
  };
};

console.log('=== DOKARAT STATS ===');
console.log('7 Days (Week: ' + weekStart + ' to ' + todayStr + '):', getStats('dokarat', weekStart, todayStr));
console.log('Current Month (' + monthStart + ' to ' + todayStr + '):', getStats('dokarat', monthStart, todayStr));

console.log('\n=== ALL GYMS NET INCOME (Week) ===');
const gyms = ['dokarat', 'marjane', 'casa1', 'casa2'];
let totalNetWeek = 0;
let totalGrossWeek = 0;
let totalDecWeek = 0;
gyms.forEach(gid => {
  const stats = getStats(gid, weekStart, todayStr);
  console.log(`${gid}:`, stats);
  totalNetWeek += stats.net;
  totalGrossWeek += stats.gross;
  totalDecWeek += stats.decaissements;
});
console.log('Total Network Week Gross:', totalGrossWeek);
console.log('Total Network Week Decaissements:', totalDecWeek);
console.log('Total Network Week Net:', totalNetWeek);
