/**
 * push_local_stats_to_firestore.js
 * ────────────────────────────────
 * Envoie les stats Door Scans recalculées du local vers FIRESTORE.
 * C'est la seule façon d'arrêter le cercle vicieux des barres plates.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
const dbLocal = require('better-sqlite3')('./megafit_cache.db');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const dbFire = admin.firestore();

async function main() {
  console.log('🚀 Envoi des vrais chiffres locaux vers Firestore...');

  const stats = dbLocal.prepare(`
    SELECT gym_id, date, count, raw_count FROM daily_stats 
    WHERE gym_id = 'dokarat' AND date >= '2026-04-10'
  `).all();

  console.log(`📊 Préparation de ${stats.length} jours...`);

  const batch = dbFire.batch();
  stats.forEach(s => {
    const docRef = dbFire.collection('gym_daily_stats').doc(`${s.gym_id}_${s.date}`);
    batch.set(docRef, { count: s.count, rawCount: s.raw_count }, { merge: true });
  });

  await batch.commit();
  console.log('✅ FIRESTORE EST RÉPARÉ !');
  console.log('Désormais, votre local et Render vont synchroniser les bons chiffres.');
  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
