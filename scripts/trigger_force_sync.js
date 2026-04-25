/**
 * trigger_force_sync.js
 * ──────────────────────
 * Appelle l'endpoint /admin/force-register-sync sur Render.
 * Cela wipe les fantômes du SQLite Render et re-pull depuis Firestore (propre).
 *
 * Usage: node trigger_force_sync.js
 */

const https = require('https');

const RENDER_BASE = 'https://megafitserverii.onrender.com';
const SECRET      = 'megafit-seed-2026'; // INJECT_SECRET

function post(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...headers,
      },
    };
    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function main() {
  console.log('\n🚀 Lancement du force-sync sur Render...\n');

  // ── 1. Vérifier que Render est up ────────────────────────────────────────
  console.log('📡 Health check...');
  try {
    const { status, body } = await post(`${RENDER_BASE}/health`, {});
    if (body?.ok) {
      console.log(`✅ Render est up (${body.ts})\n`);
    } else {
      console.log(`⚠️  Réponse inattendue:`, body);
    }
  } catch(e) {
    console.error('❌ Render inaccessible:', e.message);
    process.exit(1);
  }

  // ── 2. Force sync DOKARAT – Avril 2026 ──────────────────────────────────
  console.log('🔄 Force-sync dokarat Avril 2026...');
  try {
    const { status, body } = await post(
      `${RENDER_BASE}/admin/force-register-sync`,
      { gymId: 'dokarat', year: 2026, month: 4 },
      { 'x-inject-secret': SECRET }
    );

    if (status === 200 && body?.ok) {
      console.log('\n✅ Force-sync terminé !\n');
      console.log('Résultats :');
      for (const [gym, r] of Object.entries(body.results || {})) {
        console.log(`  ${gym}:`);
        console.log(`    🗑️  Supprimé    : ${r.wiped} lignes (fantômes)`);
        console.log(`    ✅ Re-fetché   : ${r.fetched} lignes depuis Firestore`);
        console.log(`    📭 Jours vides : ${r.skipped}`);
        console.log(`    💰 Nouveau total : ${r.newTotal.toLocaleString()} DH`);
        console.log(`    📊 Excel attendu : 755,700 DH`);
        console.log(`    📊 Écart         : ${(r.newTotal - 755700).toLocaleString()} DH`);
      }
    } else if (status === 404) {
      console.log('❌ Route non trouvée (404) — Render n\'a pas encore déployé le nouveau code.');
      console.log('   Attendez 2-3 min et relancez ce script.');
    } else if (status === 403) {
      console.log('❌ Secret invalide (403)');
    } else {
      console.log(`❌ Erreur (HTTP ${status}):`, body);
    }
  } catch(e) {
    console.error('❌ Erreur:', e.message);
  }
}

main();
