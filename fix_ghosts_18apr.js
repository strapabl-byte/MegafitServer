/**
 * fix_ghosts_18apr.js
 * ───────────────────
 * Supprime UNIQUEMENT les 2 doublons confirmés du 18 avril 2026 (DOKARAT).
 * Ces entrées existent en SQLite local mais PAS en Firestore → fantômes purs.
 *
 * Confirmé par l'utilisateur :
 *   - 5ZnTDchnK3bJMRuRkuI7  BADAR ASMAR        6,900 DH  (doublon de IoQgwN6YD8CbUc9Tg8tB)
 *   - I7mNn4TAhZD0WFWXRTbb  ABDELLAH OUBOUQSSI 5,900 DH  (doublon de Y0uWPfGLUYBQtqjv6atT)
 *
 * Résultat attendu : 66,700 → 53,900 DH pour le 18 avril (-12,800 DH)
 */

const db = require('better-sqlite3')('./megafit_cache.db');

const GHOST_IDS = [
  '5ZnTDchnK3bJMRuRkuI7',  // BADAR ASMAR doublon     → 6,900 DH
  'I7mNn4TAhZD0WFWXRTbb',  // ABDELLAH OUBOUQSSI doublon → 5,900 DH
];

// ── Avant ──────────────────────────────────────────────────────────────────
const before = db.prepare(`
  SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total,
         COUNT(*) as nb
  FROM register_cache
  WHERE gym_id='dokarat' AND date='2026-04-18'
`).get();

console.log(`\nAVANT → 18 avril : ${before.total} DH  (${before.nb} lignes)`);

// Vérifier que les IDs existent bien avant de supprimer
const toDelete = db.prepare(
  `SELECT id, nom, (CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total
   FROM register_cache WHERE id IN (${GHOST_IDS.map(() => '?').join(',')})`
).all(...GHOST_IDS);

if (toDelete.length === 0) {
  console.log('\n✅ Ces IDs sont déjà absents du SQLite. Rien à faire.');
  process.exit(0);
}

console.log('\nLignes à supprimer :');
toDelete.forEach(r => {
  console.log(`  ❌  ID: ${r.id}  |  Nom: ${r.nom}  |  Montant: ${r.total} DH`);
});

// ── Suppression atomique ────────────────────────────────────────────────────
db.transaction(() => {
  db.prepare(
    `DELETE FROM register_cache WHERE id IN (${GHOST_IDS.map(() => '?').join(',')})`
  ).run(...GHOST_IDS);
})();

// ── Après ───────────────────────────────────────────────────────────────────
const after = db.prepare(`
  SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total,
         COUNT(*) as nb
  FROM register_cache
  WHERE gym_id='dokarat' AND date='2026-04-18'
`).get();

const totalBefore = db.prepare(`
  SELECT SUM(CAST(tpe AS NUMERIC)+CAST(espece AS NUMERIC)+CAST(virement AS NUMERIC)+CAST(cheque AS NUMERIC)) as total
  FROM register_cache WHERE gym_id='dokarat' AND date>='2026-04-01' AND date<='2026-04-24'
`).get();

console.log(`\nAPRÈS  → 18 avril : ${after.total} DH  (${after.nb} lignes)`);
console.log(`\nTOTAL AVRIL (SQLite) : ${totalBefore.total} DH`);
console.log(`TOTAL ATTENDU (Excel) : 755,700 DH`);
console.log(`ÉCART RESTANT        : ${totalBefore.total - 755700} DH`);
console.log('\n✅ Suppression terminée. SQLite ≠ Firestore pour ces IDs → ils ne reviendront pas au prochain sync.');
