'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const lc = require('../localCache');

// 1. Find the member
const rows = lc.db.prepare(
  `SELECT id, full_name, gym_id, bonus_3months, expires_on FROM members_cache 
   WHERE full_name LIKE ? OR full_name LIKE ?`
).all('%FOUZIA%MEGANE%', '%MEGANE%FOUZIA%');

console.log('Found:', JSON.stringify(rows, null, 2));

if (rows.length === 0) {
  console.log('Not found in SQLite by name. Trying phone...');
  const byPhone = lc.db.prepare(
    `SELECT id, full_name, gym_id, bonus_3months, expires_on, phone FROM members_cache WHERE phone LIKE ?`
  ).all('%672488179%');
  console.log('By phone:', JSON.stringify(byPhone, null, 2));
}
