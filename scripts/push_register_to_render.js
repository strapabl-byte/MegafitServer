/**
 * push_register_to_render.js
 * ───────────────────────────
 * Lit le register_cache LOCAL (déjà propre) et l'envoie directement à Render.
 * ZÉRO appel Firestore. Zéro quota brûlé.
 *
 * Usage: node push_register_to_render.js
 */

const https  = require('https');
const db     = require('better-sqlite3')('./megafit_cache.db');

const RENDER_BASE = 'https://megafitserverii.onrender.com';
const SECRET      = 'megafit-seed-2026';
const GYM         = 'dokarat';
const DATE_FROM   = '2026-04-01';
const DATE_TO     = '2026-04-30';

function post(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data    = JSON.stringify(body);
    const urlObj  = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path:     urlObj.pathname,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
    };
    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw.slice(0, 300) }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ── Lire toutes les lignes propres du SQLite local ────────────────────────────
const rows = db.prepare(`
  SELECT
    id, gym_id, date, commercial, nom,
    CAST(tpe AS NUMERIC) as tpe,
    CAST(espece AS NUMERIC) as espece,
    CAST(virement AS NUMERIC) as virement,
    CAST(cheque AS NUMERIC) as cheque,
    CAST(prix AS NUMERIC) as prix,
    CAST(reste AS NUMERIC) as reste,
    contrat, abonnement, cin, tel, note_reste, created_at
  FROM register_cache
  WHERE gym_id = ? AND date >= ? AND date <= ?
  ORDER BY date ASC
`).all(GYM, DATE_FROM, DATE_TO);

const localTotal = rows.reduce((s, r) => s + r.tpe + r.espece + r.virement + r.cheque, 0);

console.log(`\n📦 SQLite local — ${GYM} ${DATE_FROM} → ${DATE_TO}`);
console.log(`   ${rows.length} lignes  |  Total: ${localTotal.toLocaleString()} DH`);
console.log(`   Excel attendu : 755,700 DH  |  Écart: ${localTotal - 755700} DH ${localTotal === 755700 ? '✅' : '❌'}\n`);

if (localTotal !== 755700) {
  console.log('❌ Le SQLite local n\'est pas à 755,700 DH. Vérifiez avant d\'envoyer.');
  process.exit(1);
}

async function main() {
  // 1. Push vers Render
  console.log(`🚀 Envoi de ${rows.length} lignes vers Render (0 appels Firestore)...\n`);

  const { status, body } = await post(
    `${RENDER_BASE}/admin/inject-register`,
    {
      rows,
      wipe: { gymId: GYM, dateFrom: DATE_FROM, dateTo: DATE_TO },
    },
    { 'x-inject-secret': SECRET }
  );

  if (status === 200 && body?.ok) {
    console.log(`✅ Render mis à jour !`);
    console.log(`   Lignes injectées : ${body.inserted}`);
    console.log(`   Fantômes supprimés : ${body.wiped}`);
    if (body.totals) {
      body.totals.forEach(t => {
        console.log(`   ${t.gym_id}: ${t.total?.toLocaleString()} DH (${t.nb} lignes)`);
      });
    }
  } else if (status === 404) {
    console.log('❌ Endpoint non trouvé (404) — Render n\'a pas encore déployé le nouveau code.');
    console.log('   Poussez le code et relancez ce script.');
  } else if (status === 403) {
    console.log('❌ Secret invalide.');
  } else {
    console.log(`❌ Erreur HTTP ${status}:`, body);
  }
}

main().catch(e => console.error('Erreur:', e.message));
