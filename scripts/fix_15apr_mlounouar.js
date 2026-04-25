/**
 * fix_15apr_mlounouar.js
 * ───────────────────────
 * Refetch TOUS les documents Firestore du 15 avril (sans orderBy)
 * pour récupérer Mlounouar Mostafa (5,900 DH) qui était exclu
 * à cause d'un champ createdAt manquant.
 * Puis met à jour le SQLite local.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const db  = admin.firestore();
const dbl = require('better-sqlite3')('./megafit_cache.db');

const upsert = dbl.prepare(`
  INSERT OR REPLACE INTO register_cache
    (id, gym_id, date, commercial, nom, tpe, espece, virement, cheque, prix, reste, contrat, abonnement, cin, tel, note_reste, created_at)
  VALUES
    (@id, @gym_id, @date, @commercial, @nom, @tpe, @espece, @virement, @cheque, @prix, @reste, @contrat, @abonnement, @cin, @tel, @note_reste, @created_at)
`);

function calcTotal(e) {
  return (Number(e.tpe)||0)+(Number(e.espece)||0)+(Number(e.virement)||0)+(Number(e.cheque)||0);
}

async function main() {
  console.log('\n🔍 Fetch Firestore dokarat 2026-04-15 (sans orderBy) ...\n');

  // Fetch WITHOUT orderBy — gets ALL docs including those without createdAt
  const snap = await db.collection('megafit_daily_register')
    .doc('dokarat_2026-04-15')
    .collection('entries')
    .get();  // ← no orderBy

  console.log(`📦 ${snap.size} documents trouvés dans Firestore\n`);

  let total = 0;
  const rows = [];

  snap.docs.forEach((d, i) => {
    const e = d.data();
    const t = calcTotal(e);
    total += t;
    console.log(`${String(i+1).padEnd(3)} ${d.id.padEnd(28)} ${(e.nom||'').padEnd(25)} ${String(t).padStart(8)} DH`);

    rows.push({
      id:         d.id,
      gym_id:     'dokarat',
      date:       '2026-04-15',
      commercial: e.commercial  || null,
      nom:        e.nom         || null,
      tpe:        e.tpe         ?? 0,
      espece:     e.espece      ?? 0,
      virement:   e.virement    ?? 0,
      cheque:     e.cheque      ?? 0,
      prix:       e.prix        ?? 0,
      reste:      e.reste       ?? 0,
      contrat:    e.contrat     || null,
      abonnement: e.abonnement  || null,
      cin:        e.cin         || null,
      tel:        e.tel         || null,
      note_reste: e.note_reste  || null,
      created_at: e.createdAt?.toDate?.()?.toISOString?.() || '2026-04-15',
    });
  });

  console.log(`\nTotal Firestore (sans orderBy) : ${total} DH`);
  console.log(`Excel attendu                  : 17550 DH`);
  console.log(`Écart                          : ${total - 17550} DH`);

  // Mise à jour SQLite local
  dbl.transaction(() => {
    rows.forEach(r => upsert.run(r));
  })();

  // Vérification SQLite après
  const after = dbl.prepare(`
    SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total,
           COUNT(*) as nb
    FROM register_cache WHERE gym_id='dokarat' AND date='2026-04-15'
  `).get();

  console.log(`\nSQLite local 15 avril APRÈS : ${after.total} DH (${after.nb} lignes)`);

  // Grand total Avril
  const grand = dbl.prepare(`
    SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total
    FROM register_cache WHERE gym_id='dokarat' AND date>='2026-04-01' AND date<='2026-04-30'
  `).get();

  console.log(`\n🎯 TOTAL DOKARAT AVRIL SQLite : ${grand.total} DH`);
  console.log(`   Excel attendu              : 755700 DH`);
  console.log(`   Écart final               : ${grand.total - 755700} DH  ${grand.total === 755700 ? '✅ PARFAIT !' : ''}`);
  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
