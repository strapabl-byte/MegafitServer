/**
 * rebuild_local_stats.js
 * ──────────────────────
 * Recalcule la table daily_stats à partir des scans réels (table entries).
 * Cela va réparer le graphique local instantanément.
 */

const db = require('better-sqlite3')('./megafit_cache.db');

async function main() {
  console.log('📊 Recalcul des statistiques depuis les scans réels...');

  const stats = db.prepare(`
    SELECT gym_id, date, COUNT(*) as raw_count, COUNT(DISTINCT name) as unique_count
    FROM entries 
    WHERE date >= '2026-04-01'
    GROUP BY gym_id, date
  `).all();

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count)
    VALUES (?, ?, ?, ?)
  `);

  db.transaction(() => {
    stats.forEach(s => {
      stmt.run(s.gym_id, s.date, s.unique_count, s.raw_count);
    });
  })();

  console.log(`✅ ${stats.length} jours recalculés avec succès.`);
  console.log('\n✨ Votre graphique local est maintenant RÉPARÉ !');
  process.exit(0);
}

main();
