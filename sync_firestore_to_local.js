/**
 * sync_firestore_to_local.js
 * ───────────────────────────
 * Importe TOUTES les données Firestore register_cache vers le SQLite local.
 * C'est exactement ce que Render stock (Render = Firestore sync).
 * Les fantômes locaux (absents de Firestore) sont éliminés.
 *
 * Gyms: dokarat, marjane, casa1, casa2
 * Mois : Avril 2026
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}

const db  = admin.firestore();
const dbl = require('better-sqlite3')('./megafit_cache.db');

const GYMS  = ['dokarat', 'marjane', 'casa1', 'casa2'];
const YEAR  = 2026;
const MONTH = 4;

function buildDates() {
  const dates = [];
  const end = new Date(YEAR, MONTH, 0).getDate();
  for (let d = 1; d <= end; d++) {
    dates.push(`${YEAR}-${String(MONTH).padStart(2,'0')}-${String(d).padStart(2,'0')}`);
  }
  return dates;
}

function calcTotal(e) {
  return (Number(e.tpe)||0)+(Number(e.espece)||0)+(Number(e.virement)||0)+(Number(e.cheque)||0);
}

async function main() {
  const dates = buildDates();

  console.log('\n╔══════════════════════════════════════════════════════════════════╗');
  console.log('║   IMPORT FIRESTORE → SQLite LOCAL  (Avril 2026 – tous gyms)    ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  // ── Totaux AVANT ──────────────────────────────────────────────────────────
  const beforeTotal = dbl.prepare(`
    SELECT gym_id,
           SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total,
           COUNT(*) as nb
    FROM register_cache
    WHERE date>='2026-04-01' AND date<='2026-04-30'
    GROUP BY gym_id
  `).all();

  console.log('📊 SQLite LOCAL — AVANT import :');
  let sumBefore = 0;
  beforeTotal.forEach(r => {
    console.log(`   ${r.gym_id.padEnd(10)} : ${String(r.total).padStart(8)} DH  (${r.nb} lignes)`);
    sumBefore += r.total;
  });
  console.log(`   ${'TOTAL'.padEnd(10)} : ${String(sumBefore).padStart(8)} DH\n`);

  // ── Wipe + Re-import depuis Firestore ─────────────────────────────────────
  const upsert = dbl.prepare(`
    INSERT OR REPLACE INTO register_cache
      (id, gym_id, date, commercial, nom, tpe, espece, virement, cheque, prix, reste, contrat, abonnement, cin, tel, note_reste, created_at)
    VALUES
      (@id, @gym_id, @date, @commercial, @nom, @tpe, @espece, @virement, @cheque, @prix, @reste, @contrat, @abonnement, @cin, @tel, @note_reste, @created_at)
  `);

  const upsertMany = dbl.transaction((rows) => {
    for (const r of rows) upsert.run(r);
  });

  let grandTotal = 0;
  let grandRows  = 0;

  for (const gym of GYMS) {
    // 1. Wipe local pour ce gym + mois
    const del = dbl.prepare(
      `DELETE FROM register_cache WHERE gym_id=? AND date>='2026-04-01' AND date<='2026-04-30'`
    ).run(gym);
    console.log(`🗑️  ${gym}: ${del.changes} lignes supprimées localement`);

    // 2. Fetch depuis Firestore
    let fetched = 0;
    let gymTotal = 0;

    for (const dateStr of dates) {
      const snap = await db.collection('megafit_daily_register')
        .doc(`${gym}_${dateStr}`)
        .collection('entries')
        .get();

      if (snap.empty) continue;

      const rows = snap.docs.map(d => {
        const e = d.data();
        return {
          id:          d.id,
          gym_id:      gym,
          date:        dateStr,
          commercial:  e.commercial   || null,
          nom:         e.nom          || null,
          tpe:         e.tpe          ?? 0,
          espece:      e.espece       ?? 0,
          virement:    e.virement     ?? 0,
          cheque:      e.cheque       ?? 0,
          prix:        e.prix         ?? 0,
          reste:       e.reste        ?? 0,
          contrat:     e.contrat      || null,
          abonnement:  e.abonnement   || null,
          cin:         e.cin          || null,
          tel:         e.tel          || null,
          note_reste:  e.note_reste   || null,
          created_at:  e.createdAt?.toDate?.()?.toISOString?.() || dateStr,
        };
      });

      upsertMany(rows);
      fetched += rows.length;
      gymTotal += rows.reduce((s, r) => s + calcTotal(r), 0);

      // Aussi décaissements
      const decSnap = await db.collection('megafit_daily_register')
        .doc(`${gym}_${dateStr}`)
        .collection('decaissements')
        .get();
      // décaissements stockés séparément — pas dans register_cache, on skip

      process.stdout.write('.');
    }

    grandTotal += gymTotal;
    grandRows  += fetched;
    console.log(`\n✅ ${gym}: ${fetched} lignes importées → ${gymTotal.toLocaleString()} DH`);
  }

  // ── Totaux APRÈS ──────────────────────────────────────────────────────────
  const afterTotal = dbl.prepare(`
    SELECT gym_id,
           SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total,
           COUNT(*) as nb
    FROM register_cache
    WHERE date>='2026-04-01' AND date<='2026-04-30'
    GROUP BY gym_id
  `).all();

  console.log('\n\n╔══════════════════════════════════════════════════════════════════╗');
  console.log('║                  COMPARAISON AVANT / APRÈS                      ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  let sumAfter = 0;
  afterTotal.forEach(r => {
    const before = beforeTotal.find(b => b.gym_id === r.gym_id);
    const diff = r.total - (before?.total || 0);
    const flag = diff === 0 ? '=' : diff > 0 ? `+${diff}` : `${diff}`;
    console.log(`  ${r.gym_id.padEnd(10)} : ${String(before?.total||0).padStart(8)} DH → ${String(r.total).padStart(8)} DH  (${flag} DH)  [${r.nb} lignes]`);
    sumAfter += r.total;
  });

  console.log(`\n  ${'TOTAL'.padEnd(10)} : ${String(sumBefore).padStart(8)} DH → ${String(sumAfter).padStart(8)} DH  (${sumAfter - sumBefore > 0 ? '+' : ''}${sumAfter - sumBefore} DH)`);
  console.log(`\n  Excel DOKARAT attendu : 755,700 DH`);

  const dokaratRow = afterTotal.find(r => r.gym_id === 'dokarat');
  if (dokaratRow) {
    const gap = dokaratRow.total - 755700;
    console.log(`  SQLite DOKARAT après  : ${dokaratRow.total.toLocaleString()} DH  →  écart: ${gap > 0 ? '+' : ''}${gap} DH`);
  }

  console.log('\n✅ Import terminé. SQLite local = Firestore (ce que Render devrait avoir).\n');
  process.exit(0);
}

main().catch(e => { console.error('Erreur:', e.message); process.exit(1); });
