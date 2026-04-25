const db = require('better-sqlite3')('./megafit_cache.db');
db.prepare("DELETE FROM meta WHERE key='last_register_sync'").run();
console.log('✅ Register sync cooldown cleared — next startup will force-fetch décaissements from Firestore');
