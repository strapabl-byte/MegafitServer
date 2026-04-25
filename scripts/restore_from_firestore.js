/**
 * restore_from_firestore.js
 * ─────────────────────────
 * Récupère les stats de Firestore (les bonnes !) et les remet en local.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
const dbLocal = require('better-sqlite3')('./megafit_cache.db');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const dbFire = admin.firestore();

async function main() {
  console.log('🔄 Restauration des bonnes données depuis Firestore...');

  const gyms = ['dokarat', 'marjane'];
  const today = new Date();
  
  for (const gymId of gyms) {
    console.log(`--- Restauration ${gymId} ---`);
    for (let i = 0; i < 30; i++) {
      const d = new Date();
      d.setDate(today.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      
      const snap = await dbFire.collection('gym_daily_stats').doc(`${gymId}_${dateStr}`).get();
      if (snap.exists) {
        const data = snap.data();
        dbLocal.prepare('INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count) VALUES (?, ?, ?, ?)').run(
          gymId, dateStr, data.count || 0, data.rawCount || 0
        );
      }
    }
  }

  console.log('✅ RESTAURATION TERMINÉE ! Vos bons chiffres sont de retour.');
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
