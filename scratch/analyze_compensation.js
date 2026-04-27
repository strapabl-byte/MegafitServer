'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const lc = require('../localCache');

// Criteria:
// 1. gym_id = 'dokarat'
// 2. Created/enrolled before 2025-10-31
// 3. Subscription still running (expiresOn > 2025-10-31)

const rows = lc.db.prepare(`
  SELECT id, full_name, plan, created_at, period_from, expires_on, bonus_3months
  FROM members_cache
  WHERE gym_id = 'dokarat'
    AND (
      (created_at IS NOT NULL AND created_at < '2025-10-31') OR
      (period_from IS NOT NULL AND period_from < '2025-10-31')
    )
    AND expires_on >= '2025-08-01' -- Ensure they were active around the time
`).all();

let eligible = 0;
let alreadyHasBonus = 0;

for (const row of rows) {
  if (row.bonus_3months === 1) {
    alreadyHasBonus++;
  } else {
    // Basic check to ensure they actually have a valid expiry date
    if (row.expires_on && !row.expires_on.startsWith('19')) {
      eligible++;
    }
  }
}

console.log(`Total matching general timeframe: ${rows.length}`);
console.log(`Already have bonus flag: ${alreadyHasBonus}`);
console.log(`Eligible for +3 months compensation: ${eligible}`);

// Print a few examples
const examples = rows.filter(r => r.bonus_3months === 0 && r.expires_on).slice(0, 5);
console.log('\nExamples of eligible members:');
console.table(examples);
