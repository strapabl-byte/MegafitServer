const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

console.log('Searching for matches to 88733 or 93755 in the database totals...');

// Find all unique dates in register_cache
const dates = db.prepare(`SELECT DISTINCT date FROM register_cache ORDER BY date DESC LIMIT 90`).all().map(r => r.date);

// Let's test all rolling 7-day windows for the last 60 days
for (let i = 0; i < dates.length - 7; i++) {
  const endDate = dates[i];
  const startDate = dates[i + 6]; // 7 days inclusive
  
  // Network total (with decaissements)
  let netTotal = 0;
  let grossTotal = 0;
  let dokaratGross = 0;
  let dokaratNet = 0;
  
  const gyms = ['dokarat', 'marjane', 'casa1', 'casa2'];
  gyms.forEach(gid => {
    // Gross
    const revRow = db.prepare(`
      SELECT COALESCE(SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)), 0) AS total
      FROM register_cache 
      WHERE gym_id = ? AND date >= ? AND date <= ?
    `).get(gid, startDate, endDate);
    
    // Decaissements
    const decRow = db.prepare(`
      SELECT COALESCE(SUM(CAST(montant AS NUMERIC)), 0) AS total
      FROM decaissements_cache
      WHERE gym_id = ? AND date >= ? AND date <= ? AND (status = 'approved' OR status IS NULL OR status = '')
    `).get(gid, startDate, endDate);
    
    const gross = Math.round(revRow.total);
    const dec = Math.round(decRow.total);
    const net = gross - dec;
    
    grossTotal += gross;
    netTotal += net;
    
    if (gid === 'dokarat') {
      dokaratGross = gross;
      dokaratNet = net;
    }
  });

  // Check if any of these match close to the user's values
  if (Math.abs(netTotal - 88733) < 5000 || Math.abs(dokaratGross - 93755) < 5000 || Math.abs(dokaratNet - 93755) < 5000) {
    console.log(`\nRange: ${startDate} to ${endDate}`);
    console.log(`  Network Weekly Net: ${netTotal}`);
    console.log(`  Network Weekly Gross: ${grossTotal}`);
    console.log(`  Dokarat Gross: ${dokaratGross}`);
    console.log(`  Dokarat Net: ${dokaratNet}`);
  }
}
