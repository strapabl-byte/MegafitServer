const Database = require('better-sqlite3');
const db = new Database('megafit_cache.db');
try {
    const rows = db.prepare("SELECT id, date, nom, prix, tel FROM register_cache WHERE date='2026-04-22'").all();
    console.log(JSON.stringify(rows, null, 2));
} catch (e) {
    console.error(e);
} finally {
    db.close();
}
