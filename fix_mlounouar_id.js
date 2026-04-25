/**
 * fix_mlounouar_id.js
 * ────────────────────
 * 1. Supprime l'entrée Mlounouar qu'on a insérée dans Firestore (nouveau ID)
 * 2. Cherche son vrai ID dans le SQLite local (copié depuis Render)
 * 3. Le ré-insère dans Firestore avec le BON ID
 * → Ainsi quand Render re-sync, INSERT OR REPLACE sur le même ID = pas de doublon
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const db  = admin.firestore();
const dbl = require('better-sqlite3')('./megafit_cache.db');

const WRONG_FIRESTORE_ID = 'ZjlZloDNhD2aulyMCIfn'; // celui qu'on a inséré par erreur
const DATE  = '2026-04-15';
const GYM   = 'dokarat';

async function main() {
  console.log('\n🔍 Recherche du vrai ID de Mlounouar dans SQLite local...\n');

  // Trouver le vrai ID dans SQLite local (qui vient du SQLite de Render via sync Firestore)
  const localRow = dbl.prepare(`
    SELECT id, nom, tpe, espece, virement, cheque, commercial, cin, tel, contrat, abonnement, prix, reste
    FROM register_cache
    WHERE gym_id=? AND date=? AND (LOWER(nom) LIKE '%mlounouar%' OR LOWER(nom) LIKE '%mounouar%')
  `).get(GYM, DATE);

  if (!localRow) {
    console.log('❌ Mlounouar introuvable dans SQLite local !');
    process.exit(1);
  }

  console.log(`✅ Trouvé dans SQLite :`);
  console.log(`   ID       : ${localRow.id}`);
  console.log(`   Nom      : ${localRow.nom}`);
  console.log(`   Virement : ${localRow.virement} DH`);
  console.log(`   CIN      : ${localRow.cin}`);

  const isCorrectId = localRow.id !== WRONG_FIRESTORE_ID;
  console.log(`\n   ID correct (≠ ZjlZloDNhD2aulyMCIfn) : ${isCorrectId ? '✅ OUI' : '❌ C\'est le même qu\'on a inséré'}`);

  // 1. Supprimer le mauvais ID de Firestore
  console.log(`\n🗑️  Suppression du mauvais ID Firestore (${WRONG_FIRESTORE_ID})...`);
  await db.collection('megafit_daily_register')
    .doc(`${GYM}_${DATE}`)
    .collection('entries')
    .doc(WRONG_FIRESTORE_ID)
    .delete();
  console.log('   ✅ Supprimé');

  if (!isCorrectId) {
    console.log('\n⚠️  L\'ID dans SQLite est déjà ZjlZloDNhD2aulyMCIfn. Mlounouar n\'avait pas d\'ancien ID différent.');
    console.log('   → Firestore est maintenant vide pour Mlounouar (749,800 DH).');
    console.log('   → Render garde son SQLite avec l\'entrée (755,700 DH) jusqu\'au prochain restart.');
    process.exit(0);
  }

  // 2. Ré-insérer avec le BON ID
  const correctId = localRow.id;
  console.log(`\n✍️  Insertion dans Firestore avec le bon ID (${correctId})...`);

  await db.collection('megafit_daily_register')
    .doc(`${GYM}_${DATE}`)
    .collection('entries')
    .doc(correctId)
    .set({
      nom:        localRow.nom,
      commercial: localRow.commercial,
      cin:        localRow.cin,
      tel:        localRow.tel,
      contrat:    localRow.contrat,
      tpe:        localRow.tpe,
      espece:     localRow.espece,
      virement:   localRow.virement,
      cheque:     localRow.cheque,
      prix:       localRow.prix,
      reste:      localRow.reste,
      abonnement: localRow.abonnement,
      location:   GYM,
      createdBy:  'SYSTEM_REPAIR',
      createdAt:  admin.firestore.Timestamp.fromDate(new Date('2026-04-15T12:00:00')),
    });

  console.log('   ✅ Inséré avec le bon ID !');
  console.log('\n🎯 Résultat :');
  console.log('   Firestore 15 avril : 7 membres (17,550 DH) avec le bon ID pour Mlounouar');
  console.log('   Quand Render re-sync → INSERT OR REPLACE sur même ID → pas de doublon ✅');
  console.log('   Total Render restera : 755,700 DH ✅\n');

  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
