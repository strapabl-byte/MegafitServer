/**
 * show_ghosts.js
 * ──────────────
 * Affiche TOUS les fantômes SQLite suspects pour DOKARAT – Avril 2026
 * LECTURE SEULE – aucune suppression.
 *
 * Logique : on compare le total SQLite par jour vs le total "vrai" (votre liste Excel).
 * Tout ce qui dépasse est un fantôme potentiel.
 */
const db = require('better-sqlite3')('./megafit_cache.db');

// ─── VÉRITÉ DE RÉFÉRENCE (votre liste Excel) ───────────────────────────────
const EXPECTED = {
  '2026-04-01': 39600,
  '2026-04-02': 55600,
  '2026-04-03': 45500,
  '2026-04-04': 44550,
  '2026-04-05': 4500,
  '2026-04-06': 14300,
  '2026-04-07': 38900,
  '2026-04-08': 29000,
  '2026-04-09': 38900,
  '2026-04-10': 46450,
  '2026-04-11': 24800,
  '2026-04-12': 30500,
  '2026-04-13': 18000,
  '2026-04-14': 42100,
  '2026-04-15': 17550,
  '2026-04-16': 9100,
  '2026-04-17': 55100,
  '2026-04-18': 53900,
  '2026-04-19': 6300,
  '2026-04-20': 34700,
  '2026-04-21': 42900,
  '2026-04-22': 24050,
  '2026-04-23': 20700,
  '2026-04-24': 18700,
};

// ─── CALCUL TOTAUX SQLITE ──────────────────────────────────────────────────
const sqliteDays = db.prepare(`
  SELECT date,
         SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) AS total,
         COUNT(*) as nb_rows
  FROM register_cache
  WHERE gym_id = 'dokarat'
    AND date >= '2026-04-01'
    AND date <= '2026-04-24'
  GROUP BY date
  ORDER BY date
`).all();

const sqliteByDate = {};
sqliteDays.forEach(r => { sqliteByDate[r.date] = { total: r.total, nb_rows: r.nb_rows }; });

// ─── RAPPORT PAR JOUR ──────────────────────────────────────────────────────
let totalSQLite = 0;
let totalExpected = 0;
let totalExcess = 0;

console.log('\n╔══════════════════════════════════════════════════════════════════════╗');
console.log('║        AUDIT FANTÔMES – DOKARAT – AVRIL 2026  (LECTURE SEULE)       ║');
console.log('╚══════════════════════════════════════════════════════════════════════╝\n');

const problemDates = [];

for (const [date, expected] of Object.entries(EXPECTED)) {
  const sqlite = sqliteByDate[date] || { total: 0, nb_rows: 0 };
  const diff = sqlite.total - expected;
  totalSQLite += sqlite.total;
  totalExpected += expected;
  if (diff !== 0) totalExcess += diff;

  const status = diff === 0 ? '✅' : diff > 0 ? `❌ +${diff} DH EN TROP` : `⚠️  ${diff} DH MANQUANT`;
  console.log(`${date}  |  SQLite: ${String(sqlite.total).padStart(7)} DH  |  Excel: ${String(expected).padStart(7)} DH  |  ${status}  (${sqlite.nb_rows} lignes)`);

  if (diff !== 0) problemDates.push({ date, expected, sqliteTotal: sqlite.total, diff });
}

console.log(`\n───────────────────────────────────────────────────────────────────────`);
console.log(`TOTAL SQLite   : ${totalSQLite} DH`);
console.log(`TOTAL Attendu  : ${totalExpected} DH`);
console.log(`ÉCART TOTAL    : ${totalSQLite - totalExpected} DH  ← doit être 0 après nettoyage`);

// ─── DÉTAIL LIGNE PAR LIGNE DES JOURS PROBLÉMATIQUES ──────────────────────
if (problemDates.length === 0) {
  console.log('\n✅ Aucun fantôme détecté ! Les totaux sont déjà corrects.');
  process.exit(0);
}

console.log('\n\n╔══════════════════════════════════════════════════════════════════════╗');
console.log('║              DÉTAIL DES LIGNES SUSPECTES PAR JOUR                   ║');
console.log('╚══════════════════════════════════════════════════════════════════════╝');

for (const { date, expected, sqliteTotal, diff } of problemDates) {
  const rows = db.prepare(`
    SELECT id, commercial, nom,
           CAST(tpe AS NUMERIC) as tpe,
           CAST(espece AS NUMERIC) as espece,
           CAST(virement AS NUMERIC) as virement,
           CAST(cheque AS NUMERIC) as cheque,
           (CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total
    FROM register_cache
    WHERE gym_id = 'dokarat' AND date = ?
    ORDER BY total DESC
  `).all(date);

  const diffLabel = diff > 0 ? `+${diff} DH EN TROP` : `${diff} DH MANQUANT`;
  console.log(`\n┌── ${date}  |  SQLite: ${sqliteTotal} DH  →  Attendu: ${expected} DH  (${diffLabel}) ──`);
  console.log(`│  ${'ID'.padEnd(28)} ${'Nom'.padEnd(22)} ${'Commercial'.padEnd(16)} ${'TPE'.padStart(7)} ${'Espèce'.padStart(8)} ${'Virt'.padStart(7)} ${'Chq'.padStart(7)} ${'TOTAL'.padStart(8)}`);
  console.log(`│  ${'─'.repeat(28)} ${'─'.repeat(22)} ${'─'.repeat(16)} ${'─'.repeat(7)} ${'─'.repeat(8)} ${'─'.repeat(7)} ${'─'.repeat(7)} ${'─'.repeat(8)}`);

  rows.forEach(r => {
    const flag = (r.id && r.id.startsWith('CORR_')) ? ' ← CORRECTION SYSTÈME' : '';
    console.log(`│  ${String(r.id).padEnd(28)} ${String(r.nom || '').padEnd(22)} ${String(r.commercial || '').padEnd(16)} ${String(r.tpe).padStart(7)} ${String(r.espece).padStart(8)} ${String(r.virement).padStart(7)} ${String(r.cheque).padStart(7)} ${String(r.total).padStart(8)} DH${flag}`);
  });
  console.log(`└── Sous-total SQLite: ${sqliteTotal} DH  vs  Attendu: ${expected} DH`);
}

console.log('\n\n⚠️  AUCUNE MODIFICATION N\'A ÉTÉ FAITE. C\'est un rapport de lecture seule.');
console.log('    Lancez kill_ghosts.js uniquement si vous validez les suppressions ci-dessus.\n');
