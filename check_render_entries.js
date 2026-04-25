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
  console.log('📊 Vérification des entrées (scans) sur Render...');
  
  // On teste l'endpoint des stats d'entrées
  const url = `https://megafitserverii.onrender.com/api/stats/entries?gymId=dokarat&days=7`;
  
  try {
    const res = await get(url);
    if (res.status === 200) {
      const stats = JSON.parse(res.data);
      console.log('\nHistorique des derniers jours (Entrées Uniques) :');
      stats.forEach(s => {
        console.log(`   ${s.date} : ${s.unique_entries} entrées (${s.raw_scans} scans)`);
      });
    } else {
      console.log(`❌ Erreur ${res.status} : ${res.data}`);
    }
  } catch (e) {
    console.log(`❌ Erreur de connexion : ${e.message}`);
  }
}

main();
