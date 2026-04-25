const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

async function inject() {
  const data = JSON.parse(fs.readFileSync('./seed_export.json', 'utf8'));
  const RENDER_URL = 'https://megafitserverii.onrender.com';
  const SECRET = 'megafit-seed-2026';

  console.log(`📡 Injecting ${data.daily_stats.length} rows into Render SQLite...`);

  const res = await fetch(`${RENDER_URL}/admin/inject-stats`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-inject-secret': SECRET
    },
    body: JSON.stringify(data)
  });

  const result = await res.json();
  if (result.ok) {
    console.log(`✅ SUCCESS! Injected ${result.inserted} rows into Render's SQLite.`);
  } else {
    console.error('❌ Failed:', result);
  }
}

inject().catch(console.error);
