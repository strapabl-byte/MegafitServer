const https = require('https');

async function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    }).on('error', reject);
  });
}

async function main() {
  console.log('📡 Lecture des entrées directement depuis RENDER...\n');
  
  const gyms = ['dokarat', 'marjane'];
  
  for (const gymId of gyms) {
    console.log(`--- ${gymId.toUpperCase()} ---`);
    // On essaye de récupérer les stats des 30 derniers jours via l'API de Render
    const url = `https://megafitserverii.onrender.com/api/analytics/daily-stats?gymId=${gymId}&days=30`;
    
    try {
      const res = await get(url);
      if (res.status === 200) {
        const stats = JSON.parse(res.data);
        // On affiche les 10 derniers jours pour vérifier
        stats.slice(-10).forEach(s => {
          console.log(`   ${s.date} : ${s.count} entrées (${s.raw_count} scans)`);
        });
      } else {
        console.log(`   ❌ Erreur ${res.status}`);
      }
    } catch (e) {
      console.log(`   ❌ Erreur : ${e.message}`);
    }
    console.log('');
  }
}

main();
