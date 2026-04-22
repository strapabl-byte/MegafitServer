const Database = require('better-sqlite3');
const db = new Database('./megafit_cache.db');
const rows = db.prepare(
  `SELECT contrat, commercial, nom, cin, telephone, tpe, espece, virement, cheque, note_reste
   FROM register_entries WHERE gym_id='marjane' AND date='2026-04-20' ORDER BY rowid`
).all();
console.log(`Found ${rows.length} entries:\n`);
rows.forEach(r => {
  console.log(`${String(r.contrat||'—').padEnd(6)} | ${String(r.commercial||'').padEnd(6)} | ${String(r.nom||'').padEnd(24)} | CIN:${String(r.cin||'—').padEnd(10)} | TEL:${String(r.telephone||'—').padEnd(12)} | TPE:${r.tpe} ESP:${r.espece} VIR:${r.virement} CHQ:${r.cheque} | ${r.note_reste}`);
});
db.close();
