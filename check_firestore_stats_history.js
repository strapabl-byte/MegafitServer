/**
 * check_firestore_stats_history.js
 * ────────────────────────────────
 * Liste les stats de scans enregistrées dans Firestore depuis le 02/04
 * pour voir ce que Render a synchronisé.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const dbFire = admin.firestore();

async function main() {
  const gyms = ['dokarat', 'marjane'];
  console.log('📅 Historique des entrées dans Firestore (depuis le 02/04) :\n');

  for (const gymId of gyms) {
    console.log(`--- Club : ${gymId.toUpperCase()} ---`);
    const dateStrs = [];
    for (let d = 2; d <= 25; d++) {
      dateStrs.push(`2026-04-${String(d).padStart(2, '0')}`);
    }

    const snaps = await dbFire.getAll(...dateStrs.map(d => dbFire.collection('gym_daily_stats').doc(`${gymId}_${d}`)));
    
    snaps.forEach((snap, i) => {
      const date = dateStrs[i];
      if (snap.exists) {
        const data = snap.data();
        console.log(`   ${date} : ${data.count || 0} entrées uniques (${data.rawCount || 0} scans)`);
      } else {
        console.log(`   ${date} : [VIDE]`);
      }
    });
    console.log('');
  }

  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
