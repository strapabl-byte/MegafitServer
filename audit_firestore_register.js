/**
 * audit_firestore_register.js
 * ────────────────────────────
 * Lit DIRECTEMENT Firestore (source de vérité online) pour les dates
 * problématiques de DOKARAT Avril 2026.
 * Compare avec la vérité Excel et avec le SQLite local.
 *
 * Résultat : on voit exactement ce que Firestore/Render a comme données.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';

const admin = require('firebase-admin');

if (!admin.apps.length) {
  const sa = require('./serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(sa) });
}

const db  = admin.firestore();
const dbl = require('better-sqlite3')('./megafit_cache.db');

// ─── VÉRITÉ EXCEL (24 jours) ────────────────────────────────────────────────
const EXPECTED = {
  '2026-04-01': 39600, '2026-04-02': 55600, '2026-04-03': 45500,
  '2026-04-04': 44550, '2026-04-05': 4500,  '2026-04-06': 14300,
  '2026-04-07': 38900, '2026-04-08': 29000, '2026-04-09': 38900,
  '2026-04-10': 46450, '2026-04-11': 24800, '2026-04-12': 30500,
  '2026-04-13': 18000, '2026-04-14': 42100, '2026-04-15': 17550,
  '2026-04-16': 9100,  '2026-04-17': 55100, '2026-04-18': 53900,
  '2026-04-19': 6300,  '2026-04-20': 34700, '2026-04-21': 42900,
  '2026-04-22': 24050, '2026-04-23': 20700, '2026-04-24': 18700,
};

function calcTotal(e) {
  return (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
}

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════════════════════╗');
  console.log('║   AUDIT FIRESTORE (ONLINE) vs EXCEL vs SQLite LOCAL – DOKARAT AVR 2026 ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════╝\n');

  let totalFS = 0, totalSQL = 0, totalXLS = 0;
  const problems = [];

  for (const [date, expected] of Object.entries(EXPECTED)) {
    // ── Firestore ──────────────────────────────────────────────────────────
    const snap = await db.collection('megafit_daily_register')
      .doc(`dokarat_${date}`)
      .collection('entries')
      .get();

    const fsEntries = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    const fsTotal   = fsEntries.reduce((s, e) => s + calcTotal(e), 0);

    // ── SQLite local ───────────────────────────────────────────────────────
    const sqlRows = dbl.prepare(`
      SELECT id, nom, tpe, espece, virement, cheque,
             (CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total
      FROM register_cache
      WHERE gym_id='dokarat' AND date=?
    `).all(date);
    const sqlTotal = sqlRows.reduce((s, r) => s + r.total, 0);

    totalFS  += fsTotal;
    totalSQL += sqlTotal;
    totalXLS += expected;

    const fsOk  = fsTotal  === expected ? '✅' : fsTotal  > expected ? `❌ +${fsTotal  - expected}` : `⚠️  ${fsTotal  - expected}`;
    const sqlOk = sqlTotal === expected ? '✅' : sqlTotal > expected ? `❌ +${sqlTotal - expected}` : `⚠️  ${sqlTotal - expected}`;

    console.log(`${date}  Excel:${String(expected).padStart(7)} | Firestore:${String(fsTotal).padStart(7)} ${fsOk.padEnd(14)} | SQLite:${String(sqlTotal).padStart(7)} ${sqlOk}`);

    if (fsTotal !== expected || sqlTotal !== expected) {
      problems.push({ date, expected, fsTotal, sqlTotal, fsEntries, sqlRows });
    }
  }

  console.log(`\n${'─'.repeat(85)}`);
  console.log(`TOTAL Excel     : ${totalXLS} DH`);
  console.log(`TOTAL Firestore : ${totalFS} DH  (écart: ${totalFS - totalXLS} DH)`);
  console.log(`TOTAL SQLite    : ${totalSQL} DH  (écart: ${totalSQL - totalXLS} DH)`);

  // ── Détail des jours problématiques ──────────────────────────────────────
  if (problems.length === 0) {
    console.log('\n✅ Tout est correct !');
    process.exit(0);
  }

  console.log('\n\n╔══════════════════════════════════════════════════════════════════════════╗');
  console.log('║             DÉTAIL LIGNES PAR LIGNES — JOURS PROBLÉMATIQUES              ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════╝');

  for (const p of problems) {
    console.log(`\n┌── ${p.date}  Excel: ${p.expected} DH  │  Firestore: ${p.fsTotal} DH  │  SQLite: ${p.sqlTotal} DH`);

    // IDs qui sont dans SQLite mais PAS dans Firestore → FANTÔMES
    const fsIds  = new Set(p.fsEntries.map(e => e.id));
    const sqlIds = new Set(p.sqlRows.map(r => r.id));

    const ghosts  = p.sqlRows.filter(r => !fsIds.has(r.id));
    const missing = p.fsEntries.filter(e => !sqlIds.has(e.id));

    if (ghosts.length > 0) {
      console.log(`│  🚨 FANTÔMES (dans SQLite local mais ABSENTS de Firestore) :`);
      ghosts.forEach(r => console.log(`│     ❌ ID: ${r.id.padEnd(28)} Nom: ${(r.nom||'').padEnd(25)} Montant: ${r.total} DH`));
    }

    if (missing.length > 0) {
      console.log(`│  ⚠️  MANQUANTS (dans Firestore mais ABSENTS du SQLite local) :`);
      missing.forEach(e => console.log(`│     ➕ ID: ${e.id.padEnd(28)} Nom: ${(e.nom||'').padEnd(25)} Montant: ${calcTotal(e)} DH`));
    }

    if (ghosts.length === 0 && missing.length === 0) {
      // Même IDs, mais totaux différents — chercher les CORR_ system entries
      const corrRows = p.sqlRows.filter(r => r.id && r.id.startsWith('CORR_'));
      if (corrRows.length > 0) {
        console.log(`│  🔧 CORRECTIONS SYSTÈME dans SQLite (absent Firestore) :`);
        corrRows.forEach(r => console.log(`│     🔧 ID: ${r.id.padEnd(28)} Montant: ${r.total} DH`));
      }
    }

    console.log(`│  Firestore: ${p.fsEntries.length} lignes  │  SQLite: ${p.sqlRows.length} lignes`);
    console.log(`└──`);
  }

  process.exit(0);
}

main().catch(e => { console.error('Erreur:', e.message); process.exit(1); });
