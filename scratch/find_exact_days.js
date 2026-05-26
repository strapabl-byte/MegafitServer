const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

// Generate all dates in our range
const minMax = db.prepare(`SELECT MIN(date) as minD, MAX(date) as maxD FROM register_cache`).get();
const start = new Date(minMax.minD);
const end = new Date(minMax.maxD);

const dateList = [];
let current = new Date(start);
while (current <= end) {
  dateList.push(current.toISOString().slice(0, 10));
  current.setDate(current.getDate() + 1);
}

console.log(`Checking ${dateList.length} dates from ${minMax.minD} to ${minMax.maxD}`);

const gyms = ['dokarat', 'marjane', 'casa1', 'casa2'];

// Check 7-day windows
for (let i = 0; i <= dateList.length - 7; i++) {
  const windowDates = dateList.slice(i, i + 7);
  const startW = windowDates[0];
  const endW = windowDates[windowDates.length - 1];

  // Calculate gross and net for each gym, and network total
  const gymStats = {};
  let networkGross = 0;
  let networkNet = 0;
  let networkDec = 0;

  gyms.forEach(gid => {
    // Gross
    let gross = 0;
    windowDates.forEach(d => {
      const row = db.prepare(`
        SELECT SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as total
        FROM register_cache
        WHERE gym_id = ? AND date = ?
      `).get(gid, d);
      gross += Number(row.total) || 0;
    });

    // Decaissements
    let dec = 0;
    windowDates.forEach(d => {
      const rows = db.prepare(`
        SELECT SUM(CAST(montant AS NUMERIC)) as total
        FROM decaissements_cache
        WHERE gym_id = ? AND date = ? AND (status = 'approved' OR status IS NULL OR status = '')
      `).get(gid, d);
      dec += Number(rows.total) || 0;
    });

    const net = gross - dec;
    gymStats[gid] = { gross, dec, net };

    networkGross += gross;
    networkDec += dec;
    networkNet += net;
  });

  // If any number is close to 88733 or 93755, log it!
  const isClose = (val, target, tolerance = 100) => Math.abs(val - target) <= tolerance;

  // Let's print out if we find any match
  if (
    isClose(networkNet, 88733) || 
    isClose(networkGross, 88733) ||
    isClose(gymStats.dokarat.gross, 93755) ||
    isClose(gymStats.dokarat.net, 93755) ||
    isClose(gymStats.dokarat.gross, 88733) ||
    isClose(gymStats.dokarat.net, 88733)
  ) {
    console.log(`\n--- Period: ${startW} to ${endW} ---`);
    console.log(`Network Gross: ${Math.round(networkGross)} | Dec: ${Math.round(networkDec)} | Net: ${Math.round(networkNet)}`);
    gyms.forEach(gid => {
      console.log(`  ${gid}: Gross=${Math.round(gymStats[gid].gross)} | Dec=${Math.round(gymStats[gid].dec)} | Net=${Math.round(gymStats[gid].net)}`);
    });
  }
}
