const lc = require('../localCache');
const { cleanName, findBestMatch, loadOdooCSV } = require('../lib/resubEngine');

// Simulate the resub-matrix endpoint logic
async function testResubMatrix() {
  const gymId = 'all';
  const startMonth = '2026-04';
  const endMonth = '2026-05';

  const startDate = `${startMonth}-01`;
  const endDate = `${endMonth}-31`;

  const gymIds = ['dokarat', 'marjane', 'casa1', 'casa2'];
  const placeholders = gymIds.map(() => '?').join(',');

  console.log('Querying register_cache...');
  const rows = lc.db.prepare(`
    SELECT id, gym_id, nom, date, abonnement, tel, cin,
           (tpe + espece + virement + cheque) AS total
    FROM register_cache
    WHERE gym_id IN (${placeholders})
      AND date >= ? AND date <= ?
    ORDER BY date DESC
  `).all(...gymIds, startDate, endDate);

  console.log(`Found ${rows.length} register entries.`);

  console.log('Loading Odoo CSV...');
  loadOdooCSV();

  const NOW_ISO = new Date().toISOString();

  console.log('Loading cached resub matrix entries...');
  const cachedRows = lc.db.prepare(`
    SELECT register_id, type, confidence, matched_name, prev_club, prev_gym_id,
           prev_status, last_sub, ai_verified, ai_reason, detection_mode,
           used_variant, was_split
    FROM resub_intelligence_cache
    WHERE register_id IN (${rows.map(() => '?').join(',')})
  `).all(...rows.map(r => String(r.id)));

  console.log(`Found ${cachedRows.length} cached verdicts.`);
}

testResubMatrix().catch(console.error);
