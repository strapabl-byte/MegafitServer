const Database = require('better-sqlite3');
const db = new Database('megafit_cache.db');

console.log('Total members in members_cache:', db.prepare("SELECT COUNT(*) as c FROM members_cache").get());
console.log('Expired in members_cache:', db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE expires_on != '' AND expires_on < date('now')").get());
console.log('Active in members_cache:', db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE expires_on >= date('now')").get());
console.log('No expiry date in members_cache:', db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE expires_on = '' OR expires_on IS NULL").get());
console.log('Sample expired members:', db.prepare("SELECT full_name, expires_on, birthday, phone FROM members_cache WHERE expires_on != '' AND expires_on < date('now') LIMIT 5").all());
