const db = require('better-sqlite3')('megafit_cache.db');
const rows = db.prepare("SELECT entry_key, matched_name, id_status FROM smart_identity_cache WHERE LOWER(entry_key) LIKE '%rajae%' OR LOWER(entry_key) LIKE '%bouzoubaa%'").all();
console.log('Rajae/Bouzoubaa cache:', rows);
// Also clear all non-staff entries to force full re-identification with new engine
const r = db.prepare("DELETE FROM smart_identity_cache WHERE id_status NOT IN ('staff')").run();
console.log(`Cleared ${r.changes} non-staff cache entries for fresh identification.`);
db.close();
