const lc = require('../localCache');
const today = '2026-04-27';
const gid = 'dokarat';
const limitCount = 10;

console.log(`Checking live entries for ${gid} on ${today}...`);

const entries = lc.getEntries(gid, { date: today, limit: limitCount });
console.log(`Found ${entries.length} entries in SQLite.`);

entries.forEach(e => {
  console.log(`[${e.timestamp}] ${e.name}`);
});

console.log('--- Sorting Test ---');
const merged = entries.map(e => ({
  name: e.name,
  timestamp: e.timestamp,
  displayTime: (e.timestamp || '').slice(11, 16)
}));

merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

merged.forEach(m => {
  console.log(`[${m.timestamp}] ${m.name} -> ${m.displayTime}`);
});
