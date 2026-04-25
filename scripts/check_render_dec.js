const https = require('https');

async function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    }).on('error', reject);
  });
}

async function main() {
  console.log('🔍 Recherche de l\'origine du décalage de 2,000 DH sur Render...');
  
  // On va vérifier les décaissements sur Render
  // Comme on ne peut pas lister facilement tous les décaissements d'un coup,
  // on va utiliser l'endpoint KPI qui nous donne le net.
  const url = `https://megafitserverii.onrender.com/api/kpi/daily-ca?gymId=dokarat&year=2026&month=4`;
  
  try {
    const res = await get(url);
    if (res.status === 200) {
      const data = JSON.parse(res.data);
      let totalNet = 0;
      data.forEach(d => {
        if (d.date.startsWith('2026-04')) {
          totalNet += (d.total || 0);
          if (d.decaissements > 0) {
             console.log(`💸 Décaissement le ${d.date} : ${d.decaissements} DH`);
          }
        }
      });
      console.log(`\nTotal Net Render (Calendar) : ${totalNet.toLocaleString()} DH`);
      console.log(`Total Brut Injecté           : 755,700 DH`);
      console.log(`Écart (Décaissements ?)      : ${totalNet - 755700} DH`);
    } else {
      console.log(`❌ Erreur API : ${res.status}`);
    }
  } catch (e) {
    console.log(`❌ Erreur : ${e.message}`);
  }
}

main();
