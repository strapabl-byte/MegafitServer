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
  console.log('📡 Vérification du total Dokarat Avril sur Render...');
  
  let grandTotal = 0;
  let count = 0;

  for (let d = 1; d <= 30; d++) {
    const date = `2026-04-${String(d).padStart(2, '0')}`;
    const url = `https://megafitserverii.onrender.com/api/register?date=${date}&gymId=dokarat`;
    
    try {
      const res = await get(url);
      if (res.status === 200) {
        const rows = JSON.parse(res.data);
        const dayTotal = rows.reduce((acc, row) => {
           return acc + (Number(row.tpe)||0) + (Number(row.espece)||0) + (Number(row.virement)||0) + (Number(row.cheque)||0);
        }, 0);
        grandTotal += dayTotal;
        count += rows.length;
        if (dayTotal > 0) process.stdout.write('.');
      }
    } catch (e) {
      process.stdout.write('x');
    }
  }

  console.log(`\n\n🎯 TOTAL RENDER DOKARAT AVRIL : ${grandTotal.toLocaleString()} DH`);
  console.log(`   Nombre d'entrées           : ${count}`);
  console.log(`   Cible Excel                : 755,700 DH`);
  console.log(`   Écart                      : ${grandTotal - 755700} DH`);
  
  if (grandTotal === 755700) {
    console.log('✅ TOUT EST PARFAIT !');
  } else {
    console.log('⚠️  Il y a encore un décalage.');
  }
}

main();
