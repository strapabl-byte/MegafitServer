const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('--- ALL 7-DAY ROLLING PERIODS FOR DOKARAT ---');

const dates = db.prepare(`SELECT DISTINCT date FROM register_cache WHERE gym_id = 'dokarat' ORDER BY date DESC`).all().map(r => r.date);

for (let i = 0; i < dates.length - 7; i++) {
  const endDate = dates[i];
  const startDate = dates[i + 6];

  const revRow = db.prepare(`
    SELECT COALESCE(SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)), 0) AS total
    FROM register_cache 
    WHERE gym_id = 'dokarat' AND date >= ? AND date <= ?
  `).get(startDate, endDate);

  const decRow = db.prepare(`
    SELECT COALESCE(SUM(CAST(montant AS NUMERIC)), 0) AS total
    FROM decaissements_cache
    WHERE gym_id = 'dokarat' AND date >= ? AND date <= ? AND (status = 'approved' OR status IS NULL OR status = '')
  `).get(startDate, endDate);

  const gross = Math.round(revRow.total);
  const dec = Math.round(decRow.total);
  const net = gross - dec;

  console.log(`Period: ${startDate} to ${endDate} | Gross: ${gross} | Decaissements: ${dec} | Net: ${net}`);
}
