const Database = require('better-sqlite3');
const db = new Database('C:/Users/Thatsme/Documents/MegaSolution/megafit-api/megafit_cache.db');

const member = db.prepare("SELECT * FROM members WHERE full_name LIKE '%Bouchra%'").get();
console.log("Member in SQLite:", JSON.stringify(member, null, 2));

const pending = db.prepare("SELECT * FROM pending_members").all();
console.log("Number of pending members in SQLite:", pending.length);
if (member && member.inscription_id) {
    const ins = db.prepare("SELECT * FROM pending_members WHERE id = ?").get(member.inscription_id);
    console.log("Inscription in SQLite:", JSON.stringify(ins, null, 2));
} else {
    console.log("No inscription_id found for member.");
}
