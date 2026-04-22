/**
 * Force-sync Marjane register from Firestore → SQLite for all of 2026
 * Run once: node scratch/force_sync_marjane.js
 */
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');
const lc = require('../localCache');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const GYM = 'marjane';
const YEAR = 2026;

function toLocalDateStr(d) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}

async function syncMonthRegister(gym, year, month) {
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  let totalEntries = 0;
  let totalRevenue = 0;

  for (let day = 1; day <= daysInMonth; day++) {
    const date = new Date(year, month, day);
    if (date > new Date()) break; // don't go into the future
    const dateStr = toLocalDateStr(date);
    const ref = db.collection('megafit_daily_register').doc(`${gym}_${dateStr}`).collection('entries');
    const snap = await ref.get();
    if (snap.empty) continue;
    const entries = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    lc.upsertRegister(gym, dateStr, entries);
    const dayRevenue = entries.reduce((s, e) => s + (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0), 0);
    totalEntries += entries.length;
    totalRevenue += dayRevenue;
    if (entries.length > 0) console.log(`  ✅ ${dateStr}: ${entries.length} entries — ${dayRevenue} DH`);
  }
  return { totalEntries, totalRevenue };
}

async function main() {
  const months = [0, 1, 2, 3]; // Jan–Apr 2026
  const monthNames = ['January', 'February', 'March', 'April'];
  let grandTotal = 0;
  let grandEntries = 0;

  console.log(`\n🔄 Force-syncing ${GYM.toUpperCase()} register from Firestore...\n`);
  for (const m of months) {
    console.log(`📅 ${monthNames[m]} ${YEAR}:`);
    const { totalEntries, totalRevenue } = await syncMonthRegister(GYM, YEAR, m);
    console.log(`  → ${totalEntries} entries | ${totalRevenue.toLocaleString()} DH\n`);
    grandTotal += totalRevenue;
    grandEntries += totalEntries;
  }

  console.log(`\n✨ SYNC COMPLETE for ${GYM.toUpperCase()}`);
  console.log(`   Total entries synced: ${grandEntries}`);
  console.log(`   Total revenue (tpe+espece+virement+cheque): ${grandTotal.toLocaleString()} DH`);
  console.log(`\n   Now restart the API server to see updated numbers.\n`);
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
