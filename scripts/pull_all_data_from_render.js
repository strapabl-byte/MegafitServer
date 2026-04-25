/**
 * pull_all_data_from_render.js
 * ───────────────────────────
 * Aspire les stats et les scans bruts depuis Render vers le local SQLite.
 */

const https = require('https');
const dbLocal = require('better-sqlite3')('./megafit_cache.db');

const RENDER_URL = 'https://megafitserverii.onrender.com/api/admin/export-all-stats';
const SECRET     = 'megafit-seed-2026';

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    }).on('error', reject);
  });
}

async function main() {
  console.log('📡 Aspiration des données depuis Render...');
  
  // Note: On utilise le secret dans le header pour l'auth admin
  const res = await get(RENDER_URL, { 'x-inject-secret': SECRET });

  if (res.status !== 200) {
    console.error(`❌ Échec : ${res.status}`, res.body);
    process.exit(1);
  }

  const { stats, entries } = res.body;
  console.log(`✅ Reçu : ${stats.length} jours de stats et ${entries.length} scans bruts.`);

  // Injection dans le SQLite local
  const insertStat = dbLocal.prepare('INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count) VALUES (?, ?, ?, ?)');
  const insertEntry = dbLocal.prepare('INSERT OR REPLACE INTO entries (id, gym_id, date, timestamp, name, method, status, is_face) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');

  dbLocal.transaction(() => {
    stats.forEach(s => insertStat.run(s.gym_id, s.date, s.count, s.raw_count));
    entries.forEach(e => insertEntry.run(e.id, e.gym_id, e.date, e.timestamp, e.name, e.method, e.status, e.is_face));
  })();

  console.log('✨ Base de données locale synchronisée avec Render !');
  process.exit(0);
}

main();
