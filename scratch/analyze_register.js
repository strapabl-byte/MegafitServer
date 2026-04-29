const db = require('better-sqlite3')('megafit_cache.db');

const all = db.prepare("SELECT * FROM register_cache ORDER BY date DESC").all();
console.log(`Total register entries: ${all.length}`);

// 1. RESTE: Members with outstanding balance
const avecReste = all.filter(e => Number(e.reste) > 0);
console.log(`\n=== RESTE (balance due): ${avecReste.length} entries ===`);
avecReste.slice(0, 5).forEach(e => 
  console.log(`  ${e.nom} | ${e.gym_id} | ${e.date} | reste: ${e.reste} DH | note: ${e.note_reste || 'none'}`)
);

// 2. DUPLICATES by CIN
const byCin = {};
all.forEach(e => {
  if (!e.cin) return;
  const k = e.cin.toUpperCase().trim();
  if (!byCin[k]) byCin[k] = [];
  byCin[k].push(e);
});
const dupsByCin = Object.entries(byCin).filter(([, v]) => v.length > 1);
console.log(`\n=== DUPLICATES by CIN: ${dupsByCin.length} CINs appear more than once ===`);
dupsByCin.slice(0, 5).forEach(([cin, entries]) => {
  console.log(`  CIN: ${cin}`);
  entries.forEach(e => console.log(`    ${e.nom} | ${e.gym_id} | ${e.date} | prix: ${e.prix} DH`));
});

// 3. DUPLICATES by name (fuzzy)
const byName = {};
all.forEach(e => {
  const k = (e.nom || '').toUpperCase().replace(/\s+/g, ' ').trim();
  if (!k) return;
  if (!byName[k]) byName[k] = [];
  byName[k].push(e);
});
const dupsByName = Object.entries(byName).filter(([, v]) => v.length > 1);
console.log(`\n=== DUPLICATES by name: ${dupsByName.length} names appear more than once ===`);
dupsByName.slice(0, 5).forEach(([name, entries]) => {
  console.log(`  Name: ${name}`);
  entries.forEach(e => console.log(`    ${e.gym_id} | ${e.date} | prix: ${e.prix} DH | reste: ${e.reste} DH`));
});

// 4. Summary stats
const totalReste = avecReste.reduce((s, e) => s + Number(e.reste), 0);
console.log(`\n=== FINANCIAL SUMMARY ===`);
console.log(`Total outstanding balance (reste): ${totalReste.toLocaleString()} DH`);
console.log(`Entries with reste > 0: ${avecReste.length}`);
console.log(`Unique CINs with duplicates: ${dupsByCin.length}`);
