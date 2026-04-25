/**
 * insert_mlounouar_firestore.js
 * ──────────────────────────────
 * Insère Mlounouar Mostafa (5,900 DH Virement) dans Firestore
 * pour le 15 avril 2026 DOKARAT.
 * Données extraites du screenshot du dashboard.
 * L'ID Firestore sera auto-généré (add).
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const db  = admin.firestore();
const dbl = require('better-sqlite3')('./megafit_cache.db');

async function main() {
  const GYM  = 'dokarat';
  const DATE = '2026-04-15';

  // Données du membre confirmées par le screenshot
  const entry = {
    nom:        'Mlounouar Mostafa',
    commercial: 'Ouissale',
    cin:        'C373155',
    tel:        '619991395',
    contrat:    '14351',
    tpe:        0,
    espece:     0,
    virement:   5900,
    cheque:     0,
    prix:       5900,
    reste:      0,
    abonnement: '2 ANS',
    location:   GYM,
    createdBy:  'SYSTEM_REPAIR',
    createdAt:  admin.firestore.Timestamp.fromDate(new Date('2026-04-15T12:00:00')),
  };

  console.log('\n📝 Insertion dans Firestore...');
  console.log('   Membre :', entry.nom);
  console.log('   Date   :', DATE);
  console.log('   Montant: 5,900 DH (Virement)');

  // Vérifier qu'il n'existe pas déjà
  const existing = await db.collection('megafit_daily_register')
    .doc(`${GYM}_${DATE}`)
    .collection('entries')
    .where('cin', '==', entry.cin)
    .get();

  if (!existing.empty) {
    console.log('\n⚠️  Un document avec ce CIN existe déjà dans Firestore pour cette date :');
    existing.docs.forEach(d => console.log('  ', d.id, d.data().nom));
    console.log('Annulé pour éviter doublon.');
    process.exit(0);
  }

  // Insertion
  const ref = await db.collection('megafit_daily_register')
    .doc(`${GYM}_${DATE}`)
    .collection('entries')
    .add(entry);

  // Mettre à jour le doc parent
  await db.collection('megafit_daily_register')
    .doc(`${GYM}_${DATE}`)
    .set({ gymId: GYM, date: DATE, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

  console.log(`\n✅ Inséré dans Firestore avec ID : ${ref.id}`);

  // Aussi mettre à jour SQLite local
  dbl.prepare(`
    INSERT OR REPLACE INTO register_cache
      (id, gym_id, date, commercial, nom, tpe, espece, virement, cheque, prix, reste, contrat, abonnement, cin, tel, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(ref.id, GYM, DATE, entry.commercial, entry.nom, 0, 0, 5900, 0, 5900, 0, entry.contrat, entry.abonnement, entry.cin, entry.tel, '2026-04-15');

  // Vérification finale
  const after = dbl.prepare(`
    SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total, COUNT(*) as nb
    FROM register_cache WHERE gym_id='dokarat' AND date='2026-04-15'
  `).get();

  const grand = dbl.prepare(`
    SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total
    FROM register_cache WHERE gym_id='dokarat' AND date>='2026-04-01' AND date<='2026-04-30'
  `).get();

  console.log(`\n15 avril SQLite : ${after.total} DH (${after.nb} lignes)`);
  console.log(`\n🎯 TOTAL DOKARAT AVRIL : ${grand.total} DH`);
  console.log(`   Excel attendu       : 755700 DH`);
  console.log(`   Écart final         : ${grand.total - 755700} DH  ${grand.total === 755700 ? '✅ PARFAIT !' : ''}`);

  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
