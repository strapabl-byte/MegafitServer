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
  console.log('📡 Audit Profond de Render (Dokarat Avril)...');
  
  const expected = [
    39600, 55600, 45500, 44550, 4500, 14300, 38900, 29000, 38900, 46450, 
    24800, 30500, 18000, 42100, 17550, 9100, 55100, 53900, 6300, 34700, 
    42900, 24050, 20700, 18700
  ];

  let totalReg = 0;

  for (let i = 1; i <= 24; i++) {
    const date = `2026-04-${String(i).padStart(2, '0')}`;
    // On utilise l'endpoint public pour voir ce que le dashboard voit
    const url = `https://megafitserverii.onrender.com/api/register?date=${date}&gymId=dokarat`;
    
    try {
      const res = await get(url);
      if (res.status === 200) {
        const rows = JSON.parse(res.data);
        const dayTotal = rows.reduce((acc, row) => acc + (Number(row.tpe)||0) + (Number(row.espece)||0) + (Number(row.virement)||0) + (Number(row.cheque)||0), 0);
        const exp = expected[i-1];
        
        if (dayTotal !== exp) {
          console.log(`❌ ${date}: Render=${dayTotal} | Attendu=${exp} | Écart=${dayTotal-exp}`);
        } else {
          console.log(`✅ ${date}: ${dayTotal} DH`);
        }
        totalReg += dayTotal;
      }
    } catch (e) {
      console.log(`⚠️ ${date}: Erreur de fetch`);
    }
  }

  console.log(`\nTOTAL RÉEL SUR RENDER : ${totalReg.toLocaleString()} DH`);
  console.log(`CIBLE EXCEL           : 755,700 DH`);
}

main();
