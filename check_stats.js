// check_stats.js - Check what's in gym_daily_stats for the last 7 days
const admin = require('firebase-admin');
const sa = require('./serviceAccount.json');
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });
const db = admin.firestore();

async function run() {
    const snap = await db.collection('gym_daily_stats').where('gym_id', '==', 'dokarat').get();
    const docs = snap.docs.map(d => d.data()).sort((a, b) => b.date.localeCompare(a.date)).slice(0, 7);
    console.log('Last 7 Dokarat entries in gym_daily_stats:');
    docs.forEach(d => console.log(`  ${d.date}: count=${d.count}`));

    const snap2 = await db.collection('gym_daily_stats').where('gym_id', '==', 'marjane').get();
    const docs2 = snap2.docs.map(d => d.data()).sort((a, b) => b.date.localeCompare(a.date)).slice(0, 7);
    console.log('\nLast 7 Marjane entries in gym_daily_stats:');
    docs2.forEach(d => console.log(`  ${d.date}: count=${d.count}`));

    process.exit(0);
}
run().catch(e => { console.error(e.message); process.exit(1); });
