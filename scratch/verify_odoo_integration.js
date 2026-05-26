const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'megafit_cache.db');
console.log('Opening SQLite DB:', DB_PATH);
const db = new Database(DB_PATH);

try {
  // Test 1: Count Odoo members in SQLite
  const total = db.prepare('SELECT COUNT(*) as c FROM odoo_members_cache').get().c;
  console.log('✅ Odoo members count in SQLite:', total);

  // Test 2: Simulate building the IN clause for 'all' and individual gyms
  const testGyms = ['all', 'dokarat', 'marjane', 'casa1', 'casa2'];
  
  for (const gymId of testGyms) {
    const getGymIds = (gId) => {
      if (!gId || gId === 'all') return [];
      if (Array.isArray(gId)) return gId;
      return String(gId).split(',').map(s => s.trim()).filter(Boolean);
    };
    const buildInClause = (gymIds, prefix = 'gym_id') => {
      if (gymIds.length === 0) return { sql: '1=1', params: [] };
      const placeholders = gymIds.map(() => '?').join(',');
      return { sql: `${prefix} IN (${placeholders})`, params: gymIds };
    };

    const odooGymIds = getGymIds(gymId);
    const odooClause = buildInClause(odooGymIds);
    const odooRows = db.prepare(`SELECT * FROM odoo_members_cache WHERE ${odooClause.sql}`).all(...odooClause.params);
    
    console.log(`  - Gym [${gymId}]: Found ${odooRows.length} Odoo members`);
  }

  // Test 3: Test single member lookup
  const single = db.prepare('SELECT * FROM odoo_members_cache LIMIT 1').get();
  if (single) {
    console.log('✅ Found single Odoo member for details check:', single.full_name, '(ID:', single.id, ')');
  } else {
    console.warn('⚠️ No Odoo members found in table.');
  }

  console.log('🎉 Verification script completed successfully!');
} catch (err) {
  console.error('❌ Error during database query execution:', err);
} finally {
  db.close();
}
