/**
 * audit_render_register.js
 * ─────────────────────────
 * Compare le registre Render (online SQLite) vs local SQLite pour DOKARAT Avril 2026.
 * Utilise le endpoint /api/kpi/daily-ca qui ne nécessite PAS de token Azure.
 * Puis compare ligne par ligne pour les dates problématiques via /api/register (avec token si dispo).
 */

const https = require('https');

const RENDER_BASE = 'https://megafitserverii.onrender.com';

// ─── VÉRITÉ DE RÉFÉRENCE (Excel) ───────────────────────────────────────────
const EXPECTED = {
  '2026-04-01': 39600, '2026-04-02': 55600, '2026-04-03': 45500,
  '2026-04-04': 44550, '2026-04-05': 4500,  '2026-04-06': 14300,
  '2026-04-07': 38900, '2026-04-08': 29000, '2026-04-09': 38900,
  '2026-04-10': 46450, '2026-04-11': 24800, '2026-04-12': 30500,
  '2026-04-13': 18000, '2026-04-14': 42100, '2026-04-15': 17550,
  '2026-04-16': 9100,  '2026-04-17': 55100, '2026-04-18': 53900,
  '2026-04-19': 6300,  '2026-04-20': 34700, '2026-04-21': 42900,
  '2026-04-22': 24050, '2026-04-23': 20700, '2026-04-24': 18700,
};

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ raw: data.slice(0, 200) }); }
      });
    }).on('error', reject);
  });
}

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════════════╗');
  console.log('║     AUDIT RENDER (ONLINE) – DOKARAT – AVRIL 2026               ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  // ── 1. Tenter le endpoint /api/kpi/daily-ca (pas de token requis) ──────────
  console.log('📡 Tentative /api/kpi/daily-ca?gymId=dokarat&year=2026&month=4 ...');
  try {
    const kpi = await get(`${RENDER_BASE}/api/kpi/daily-ca?gymId=dokarat&year=2026&month=4`);
    if (kpi && kpi.dailyCa) {
      console.log('\n✅ Réponse reçue — CA journalier Render :\n');
      let renderTotal = 0;
      let expectedTotal = 0;
      const lines = [];
      for (const [date, expected] of Object.entries(EXPECTED)) {
        const day = date.split('-')[2]; // '01', '02' ...
        const renderVal = kpi.dailyCa[date] || kpi.dailyCa[day] || 0;
        const diff = renderVal - expected;
        renderTotal += renderVal;
        expectedTotal += expected;
        const status = diff === 0 ? '✅' : diff > 0 ? `❌ +${diff}` : `⚠️  ${diff}`;
        lines.push(`  ${date}  Render: ${String(renderVal).padStart(7)} DH  Excel: ${String(expected).padStart(7)} DH  ${status}`);
      }
      lines.forEach(l => console.log(l));
      console.log(`\n  TOTAL RENDER  : ${renderTotal} DH`);
      console.log(`  TOTAL EXCEL   : ${expectedTotal} DH`);
      console.log(`  ÉCART         : ${renderTotal - expectedTotal} DH`);
    } else {
      console.log('⚠️  Réponse inattendue :', JSON.stringify(kpi).slice(0, 300));
    }
  } catch(e) {
    console.log('❌ Erreur :', e.message);
  }

  // ── 2. Tenter le endpoint /api/kpi (résumé global) ─────────────────────────
  console.log('\n\n📡 Tentative /api/kpi?gymId=dokarat ...');
  try {
    const kpi2 = await get(`${RENDER_BASE}/api/kpi?gymId=dokarat`);
    console.log('Réponse KPI global :', JSON.stringify(kpi2).slice(0, 500));
  } catch(e) {
    console.log('❌ Erreur :', e.message);
  }

  // ── 3. Health check ────────────────────────────────────────────────────────
  console.log('\n📡 Health check /health ...');
  try {
    const health = await get(`${RENDER_BASE}/health`);
    console.log('Health :', JSON.stringify(health).slice(0, 300));
  } catch(e) {
    console.log('❌ Erreur :', e.message);
  }
}

main();
