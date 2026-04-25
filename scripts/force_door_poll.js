/**
 * force_door_poll.js
 * ───────────────────
 * Force le serveur local à interroger les badgeuses pour les 15 derniers jours
 * au lieu de 7, afin de tenter de récupérer les scans perdus.
 */

const axios = require('axios');
const db = require('better-sqlite3')('./megafit_cache.db');

// Config des badgeuses (depuis votre archi habituelle)
const DEVICES = {
  dokarat: 'http://192.168.1.201:8080', // À adapter si different
  marjane: 'http://192.168.1.202:8080'
};

async function forcePoll(gymId) {
  console.log(`📡 Force Poll ${gymId}...`);
  try {
    // On demande les 15 derniers jours à la badgeuse
    const res = await axios.get(`${DEVICES[gymId]}/api/logs?days=15`, { timeout: 10000 });
    const logs = res.data; // [{id, time, user_id, ...}]
    
    console.log(`   Reçu ${logs.length} scans bruts.`);
    
    const stmt = db.prepare(`INSERT OR IGNORE INTO entries (id, gym_id, user_id, time, date) VALUES (?, ?, ?, ?, ?)`);
    
    let added = 0;
    db.transaction(() => {
      logs.forEach(log => {
        const date = log.time.split(' ')[0];
        const info = stmt.run(`${gymId}_${log.id}`, gymId, log.user_id, log.time, date);
        if (info.changes > 0) added++;
      });
    })();
    
    console.log(`   ✅ ${added} nouveaux scans ajoutés au SQLite local.`);
    
    // Recalculer les stats quotidiennes
    console.log(`   📊 Recalcul des stats journalières...`);
    const stats = db.prepare(`
      SELECT date, COUNT(*) as raw_count, COUNT(DISTINCT user_id) as unique_count
      FROM entries WHERE gym_id = ? GROUP BY date
    `).all(gymId);
    
    const upstmt = db.prepare(`INSERT OR REPLACE INTO daily_stats (gym_id, date, count, raw_count) VALUES (?, ?, ?, ?)`);
    db.transaction(() => {
      stats.forEach(s => upstmt.run(gymId, s.date, s.unique_count, s.raw_count));
    })();
    
  } catch (e) {
    console.error(`   ❌ Échec ${gymId}: ${e.message}`);
  }
}

async function main() {
  await forcePoll('dokarat');
  await forcePoll('marjane');
  console.log('\n✨ Terminé. Vérifiez votre graphique local.');
  process.exit(0);
}

main();
