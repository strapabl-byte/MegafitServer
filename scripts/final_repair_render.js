/**
 * final_repair_render.js
 * ──────────────────────
 * Envoie les stats REELLES (recalculées) de Dokarat à Render.
 */

const https = require('https');
const dbLocal = require('better-sqlite3')('./megafit_cache.db');

const RENDER_BASE = 'https://megafitserverii.onrender.com';
const SECRET      = 'megafit-seed-2026';

function post(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
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
  console.log('🚀 Injection des stats RÉELLES vers Render...');

  const stats = dbLocal.prepare(`
    SELECT gym_id, date, count, raw_count FROM daily_stats 
    WHERE gym_id = 'dokarat' AND date >= '2026-04-01'
  `).all();

  // On envoie les stats avec la clé 'stats' attendue par le serveur
  const res = await post(`${RENDER_BASE}/admin/inject-stats`, { stats }, { 'x-inject-secret': SECRET });

  if (res.status === 200) {
    console.log(`✅ Succès ! ${stats.length} jours de stats injectés sur Render.`);
    console.log('✨ Le graphique online est maintenant RÉPARÉ.');
  } else {
    console.log(`❌ Échec : ${res.status}`, res.body);
  }
  process.exit(0);
}

main();
