/**
 * fix_local_stats.js
 * ──────────────────
 * Récupère les stats de scans depuis Firestore (Source de vérité)
 * et met à jour le SQLite LOCAL pour réparer le graphique.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
const dbLocal = require('better-sqlite3')('./megafit_cache.db');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const dbFire = admin.firestore();

async function main() {
  const gyms = ['dokarat', 'marjane'];
  console.log('📡 Récupération des stats depuis Firestore pour Dokarat et Marjane...\n');

  for (const gymId of gyms) {
    const dateStrs = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date(Date.now() + 3600000 - i * 86400000).toISOString().slice(0, 10);
      dateStrs.push(d);
    }

    const snaps = await dbFire.getAll(...dateStrs.map(d => dbFire.collection('gym_daily_stats').doc(`${gymId}_${d}`)));
    
    let count = 0;
    const stmt = dbLocal.prepare(`
      INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count)
      VALUES (?, ?, ?, ?)
    `);

    dbLocal.transaction(() => {
      snaps.forEach((snap, i) => {
        if (snap.exists) {
          const data = snap.data();
          stmt.run(gymId, dateStrs[i], data.count || 0, data.rawCount || 0);
          count++;
        }
      });
    })();

    console.log(`✅ [${gymId}] ${count} jours mis à jour en local.`);
  }

  console.log('\n✨ Local réparé ! Rafraîchissez votre Dashboard local.');
  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
