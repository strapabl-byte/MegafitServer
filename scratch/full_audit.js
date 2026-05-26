
/**
 * full_audit.js — Comprehensive Data Quality Check
 * Checks SQLite cache health across all tables and gyms.
 */
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, '..', 'megafit_cache.db'));

const GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
const today = new Date().toISOString().slice(0, 10);

function section(title) {
  console.log('\n' + '═'.repeat(60));
  console.log(`  ${title}`);
  console.log('═'.repeat(60));
}

function row(label, value, warn = false) {
  const icon = warn ? '⚠️ ' : '   ';
  console.log(`${icon}${label.padEnd(40)} ${String(value)}`);
}

// ── 1. MEMBERS CACHE ────────────────────────────────────────────
section('1. MEMBERS CACHE — Global Health');

const totalMembers = db.prepare("SELECT COUNT(*) as c FROM members_cache").get().c;
const archivedMembers = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE is_archive = 1").get().c;
const activeMembers = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE is_archive = 0").get().c;
const expiredMembers = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE expires_on != '' AND expires_on < date('now') AND is_archive = 0").get().c;
const activeValid = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE expires_on >= date('now') AND is_archive = 0").get().c;
const noExpiry = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE (expires_on = '' OR expires_on IS NULL) AND is_archive = 0").get().c;
const withBalance = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE balance > 0 AND is_archive = 0").get().c;
const withBalanceNoDeadline = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE balance > 0 AND is_archive = 0 AND (balance_deadline IS NULL OR balance_deadline = '')").get().c;
const noPhone = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE (phone = '' OR phone IS NULL) AND is_archive = 0").get().c;
const noBirthday = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE (birthday = '' OR birthday IS NULL) AND is_archive = 0").get().c;
const noCIN = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE (cin = '' OR cin IS NULL) AND is_archive = 0").get().c;
const unknownGym = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE gym_id NOT IN ('dokarat','marjane','casa1','casa2')").get().c;

row('Total members (all)', totalMembers);
row('  → Active (non-archived)', activeMembers);
row('  → Archived', archivedMembers);
row('Valid subscription (not expired)', activeValid);
row('Expired subscription (still active)', expiredMembers, expiredMembers > 0);
row('No expiry date', noExpiry, noExpiry > 50);
row('Has balance/debt', withBalance);
row('Has balance but NO deadline', withBalanceNoDeadline, withBalanceNoDeadline > 0);
row('No phone number', noPhone, noPhone > 100);
row('No birthday', noBirthday, noBirthday > 200);
row('No CIN', noCIN, noCIN > 200);
row('Unknown gym_id', unknownGym, unknownGym > 0);

section('1b. MEMBERS — Per Gym Breakdown');
for (const gym of GYMS) {
  const total = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE gym_id=? AND is_archive=0").get(gym).c;
  const valid = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE gym_id=? AND is_archive=0 AND expires_on >= date('now')").get(gym).c;
  const expired = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE gym_id=? AND is_archive=0 AND expires_on != '' AND expires_on < date('now')").get(gym).c;
  const debtors = db.prepare("SELECT COUNT(*) as c FROM members_cache WHERE gym_id=? AND is_archive=0 AND balance > 0").get(gym).c;
  const synced = db.prepare("SELECT MAX(synced_at) as s FROM members_cache WHERE gym_id=?").get(gym).s;
  console.log(`\n  📍 ${gym.toUpperCase()}`);
  row('    Active members', total);
  row('    Valid subscriptions', valid);
  row('    Expired subscriptions', expired, expired > 0);
  row('    Debtors', debtors, debtors > 0);
  row('    Last synced', synced || 'NEVER', !synced);
}

// Duplicate CIN check
section('1c. DUPLICATE CIN CHECK');
const dupCINs = db.prepare(`
  SELECT cin, COUNT(*) as cnt, GROUP_CONCAT(gym_id) as gyms 
  FROM members_cache 
  WHERE cin != '' AND cin IS NOT NULL AND is_archive = 0 
  GROUP BY cin HAVING cnt > 1 
  ORDER BY cnt DESC LIMIT 10
`).all();
if (dupCINs.length === 0) {
  row('Duplicate CINs', '✅ NONE');
} else {
  row('Duplicate CINs found', dupCINs.length, true);
  dupCINs.slice(0, 5).forEach(d => console.log(`   ⚠️  CIN: ${d.cin}  ×${d.cnt}  gyms: ${d.gyms}`));
}

// ── 2. REGISTER CACHE ──────────────────────────────────────────
section('2. REGISTER CACHE — Payments Health');
const totalRegister = db.prepare("SELECT COUNT(*) as c FROM register_cache").get().c;
const registerThisMonth = db.prepare("SELECT COUNT(*) as c FROM register_cache WHERE date >= date('now','start of month')").get().c;
const registerToday = db.prepare("SELECT COUNT(*) as c FROM register_cache WHERE date = ?").get(today).c;
const noCommercial = db.prepare("SELECT COUNT(*) as c FROM register_cache WHERE (commercial = '' OR commercial IS NULL)").get().c;
const zeroPrice = db.prepare("SELECT COUNT(*) as c FROM register_cache WHERE prix = 0 AND tpe = 0 AND espece = 0 AND virement = 0 AND cheque = 0").get().c;
const withReste = db.prepare("SELECT COUNT(*) as c FROM register_cache WHERE reste > 0").get().c;

row('Total register entries', totalRegister);
row('This month', registerThisMonth);
row('Today', registerToday);
row('Missing commercial name', noCommercial, noCommercial > 0);
row('Zero payment (all methods = 0)', zeroPrice, zeroPrice > 0);
row('With remaining balance (reste)', withReste);

const revenueByGym = db.prepare(`
  SELECT gym_id, SUM(tpe+espece+virement+cheque) as total, COUNT(*) as cnt
  FROM register_cache WHERE date >= date('now','start of month')
  GROUP BY gym_id ORDER BY total DESC
`).all();
console.log('\n  💰 Revenue this month by gym:');
revenueByGym.forEach(r => console.log(`     ${r.gym_id.padEnd(12)} ${r.cnt} entries  →  ${Math.round(r.total || 0)} MAD`));

// ── 3. ENTRIES (DOOR SCANNER) ──────────────────────────────────
section('3. DOOR ENTRIES — Health Check');
const totalEntries = db.prepare("SELECT COUNT(*) as c FROM entries").get().c;
const todayEntries = db.prepare("SELECT COUNT(*) as c FROM entries WHERE date = ?").get(today).c;
const noNameEntries = db.prepare("SELECT COUNT(*) as c FROM entries WHERE (name = '' OR name IS NULL)").get().c;
const oldestEntry = db.prepare("SELECT MIN(date) as d FROM entries").get().d;
const newestEntry = db.prepare("SELECT MAX(date) as d FROM entries").get().d;

row('Total door entries', totalEntries);
row('Today entries', todayEntries);
row('Entries with no name', noNameEntries, noNameEntries > 100);
row('Date range', `${oldestEntry || '?'} → ${newestEntry || '?'}`);

console.log('\n  📅 Last 7 days by gym:');
for (const gym of GYMS) {
  const week = db.prepare(`SELECT date, COUNT(*) as cnt FROM entries WHERE gym_id=? AND date >= date('now','-7 days') GROUP BY date ORDER BY date DESC LIMIT 7`).all(gym);
  const total7d = week.reduce((s, r) => s + r.cnt, 0);
  console.log(`     ${gym.padEnd(12)} ${total7d} entries this week`);
}

// ── 4. DAILY STATS ─────────────────────────────────────────────
section('4. DAILY STATS — Coverage Check');
const totalStats = db.prepare("SELECT COUNT(*) as c FROM daily_stats").get().c;
const statsOldest = db.prepare("SELECT MIN(date) as d FROM daily_stats").get().d;
const statsNewest = db.prepare("SELECT MAX(date) as d FROM daily_stats").get().d;
const zeroStats = db.prepare("SELECT COUNT(*) as c FROM daily_stats WHERE count = 0 AND date < date('now')").get().c;

row('Total daily stat records', totalStats);
row('Date range', `${statsOldest || '?'} → ${statsNewest || '?'}`);
row('Zero-count past days', zeroStats, zeroStats > 10);

// ── 5. PENDING MEMBERS ─────────────────────────────────────────
section('5. PENDING INSCRIPTIONS');
const totalPending = db.prepare("SELECT COUNT(*) as c FROM pending_cache").get().c;
const pendingByStatus = db.prepare("SELECT status, COUNT(*) as c FROM pending_cache GROUP BY status ORDER BY c DESC").all();
const pendingNoGym = db.prepare("SELECT COUNT(*) as c FROM pending_cache WHERE (gym_id = '' OR gym_id IS NULL)").get().c;

row('Total pending records', totalPending);
pendingByStatus.forEach(r => row(`  Status: ${r.status}`, r.c));
row('Missing gym_id', pendingNoGym, pendingNoGym > 0);

// ── 6. RELANCE SYSTEM ──────────────────────────────────────────
section('6. RELANCE SYSTEM');
const totalBirthdays = db.prepare("SELECT COUNT(*) as c FROM relance_birthdays").get().c;
const bdByGym = db.prepare("SELECT gym_id, COUNT(*) as c FROM relance_birthdays GROUP BY gym_id").all();
const totalCalls = db.prepare("SELECT COUNT(*) as c FROM relance_calls").get().c;
const calledCalls = db.prepare("SELECT COUNT(*) as c FROM relance_calls WHERE called = 1").get().c;

row('Birthday records loaded', totalBirthdays, totalBirthdays === 0);
bdByGym.forEach(r => row(`  ${r.gym_id}`, r.c));
row('Total relance call logs', totalCalls);
row('Calls marked as done', calledCalls);

// ── 7. INCIDENTS ───────────────────────────────────────────────
section('7. INCIDENTS');
const totalIncidents = db.prepare("SELECT COUNT(*) as c FROM incidents_cache").get().c;
const openIncidents = db.prepare("SELECT COUNT(*) as c FROM incidents_cache WHERE status = 'Pending'").get().c;
row('Total incidents', totalIncidents);
row('Open/Pending incidents', openIncidents, openIncidents > 0);

// ── 8. DECAISSEMENTS ───────────────────────────────────────────
section('8. DECAISSEMENTS (Cash Withdrawals)');
const totalDec = db.prepare("SELECT COUNT(*) as c FROM decaissements_cache").get().c;
const pendingDec = db.prepare("SELECT COUNT(*) as c FROM decaissements_cache WHERE status != 'approved'").get().c;
const thisMonthDec = db.prepare("SELECT SUM(montant) as s FROM decaissements_cache WHERE status='approved' AND date >= date('now','start of month')").get().s;

row('Total decaissements', totalDec);
row('Pending approval', pendingDec, pendingDec > 0);
row('Approved total this month', `${Math.round(thisMonthDec || 0)} MAD`);

// ── 9. SUMMARY ─────────────────────────────────────────────────
section('✅ AUDIT SUMMARY');
const issues = [];
if (unknownGym > 0) issues.push(`${unknownGym} members with unknown gym_id`);
if (withBalanceNoDeadline > 0) issues.push(`${withBalanceNoDeadline} debtors with no deadline`);
if (noCommercial > 0) issues.push(`${noCommercial} register entries missing commercial`);
if (zeroPrice > 0) issues.push(`${zeroPrice} register entries with 0 payment`);
if (dupCINs.length > 0) issues.push(`${dupCINs.length} duplicate CINs detected`);
if (totalBirthdays === 0) issues.push('Birthday table is EMPTY — relance will not work');
if (openIncidents > 0) issues.push(`${openIncidents} unresolved incidents`);
if (pendingDec > 0) issues.push(`${pendingDec} decaissements pending approval`);

if (issues.length === 0) {
  console.log('\n  ✅ ALL CHECKS PASSED — Data looks clean!');
} else {
  console.log(`\n  ⚠️  ${issues.length} ISSUE(S) FOUND:`);
  issues.forEach((i, n) => console.log(`     ${n+1}. ${i}`));
}

console.log('\n  Database size: ' + Math.round(require('fs').statSync(require('path').join(__dirname, '..', 'megafit_cache.db')).size / 1024) + ' KB');
console.log('  WAL file: ' + Math.round((require('fs').existsSync(require('path').join(__dirname, '..', 'megafit_cache.db-wal')) ? require('fs').statSync(require('path').join(__dirname, '..', 'megafit_cache.db-wal')).size : 0) / 1024) + ' KB');
console.log('  Audit ran at: ' + new Date().toISOString());
console.log('');
