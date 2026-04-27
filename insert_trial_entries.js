const db = require('better-sqlite3')('megafit_cache.db');

const active = db.prepare(`SELECT full_name, expires_on FROM members_cache WHERE expires_on >= date('now') LIMIT 1`).get();
const expired = db.prepare(`SELECT full_name, expires_on FROM members_cache WHERE expires_on != '' AND expires_on < date('now') LIMIT 1`).get();

console.log('Test Subjects:', { active, expired });

if (!active || !expired) {
  console.log('Could not find active/expired members');
  process.exit(1);
}

const today = new Date();
const timeStr = (mins) => {
  const d = new Date(today.getTime() - mins * 60000);
  return d.toISOString().slice(0, 19).replace('T', ' ');
};
const dateStr = today.toISOString().slice(0, 10);

const insertStmt = db.prepare(`
  INSERT INTO entries (id, gym_id, name, date, timestamp, method, status, is_face)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

insertStmt.run('test-active', 'dokarat', active.full_name, dateStr, timeStr(1), 'Face', 'Success', 1);
insertStmt.run('test-expired', 'dokarat', expired.full_name, dateStr, timeStr(2), 'Fingerprint', 'Success', 0);
insertStmt.run('test-unknown', 'dokarat', 'JOHN DOE UNKNOWN', dateStr, timeStr(3), 'Face', 'Success', 1);

console.log('✅ Trial entries inserted for Doukkarate.');
