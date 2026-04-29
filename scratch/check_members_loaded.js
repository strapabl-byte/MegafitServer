const lc = require('../localCache');
const marjane = lc.db.prepare("SELECT COUNT(*) as c FROM odoo_members_cache WHERE gym_id='marjane'").get().c;
const dokarat = lc.db.prepare("SELECT COUNT(*) as c FROM odoo_members_cache WHERE gym_id='dokarat'").get().c;
const cached  = lc.db.prepare("SELECT COUNT(*) as c FROM smart_identity_cache").get().c;
console.log(`📊 Marjane members in SQLite : ${marjane}`);
console.log(`📊 Dokarat members in SQLite : ${dokarat}`);
console.log(`🤖 Smart identity cache rows : ${cached}`);
process.exit(0);
