/**
 * swap_gym_stats.js
 * ─────────────────
 * Échange les statistiques entre Dokarat et Marjane pour les jours 
 * où les données ont été inversées (Avril 2026).
 */

const db = require('better-sqlite3')('./megafit_cache.db');

async function main() {
  console.log('🔄 Inversion des statistiques entre Dokarat et Marjane...');

  // On récupère toutes les stats d'avril
  const stats = db.prepare(`SELECT * FROM daily_stats WHERE date >= '2026-04-01' AND date <= '2026-04-30'`).all();

  const stmt = db.prepare(`UPDATE daily_stats SET count = ?, raw_count = ? WHERE gym_id = ? AND date = ?`);

  db.transaction(() => {
    // Pour chaque jour, on trouve les deux clubs et on inverse leurs valeurs
    const dates = [...new Set(stats.map(s => s.date))];
    
    dates.forEach(date => {
      const dStats = stats.find(s => s.date === date && s.gym_id === 'dokarat');
      const mStats = stats.find(s => s.date === date && s.gym_id === 'marjane');
      
      if (dStats && mStats) {
        // On donne les valeurs de Marjane à Dokarat
        stmt.run(mStats.count, mStats.raw_count, 'dokarat', date);
        // On donne les valeurs de Dokarat à Marjane
        stmt.run(dStats.count, dStats.raw_count, 'marjane', date);
      }
    });
  })();

  console.log('✅ Inversion terminée en local.');
  process.exit(0);
}

main();
