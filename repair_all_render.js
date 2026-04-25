/**
 * repair_all_render.js
 * ──────────────────────
 * 1. Fetch les stats Door Scans depuis Firestore (Source de vérité pour le graphique)
 * 2. Lit le Registre local Propre (755,700 DH)
 * 3. Envoie TOUT à Render via les endpoints /admin/inject-...
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
const https = require('https');
const dbLocal = require('better-sqlite3')('./megafit_cache.db');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const dbFire = admin.firestore();

const RENDER_BASE = 'https://megafitserverii.onrender.com';
const SECRET      = 'megafit-seed-2026';
const GYM         = 'dokarat';

function post(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
    };
    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function main() {
  console.log('🛠️  DÉBUT DE LA RÉPARATION GLOBALE RENDER...\n');

  // ── STEP 1: Fetch Door Stats from Firestore ───────────────────────────────
  console.log('📡 Récupération des statistiques de scans depuis Firestore...');
  const stats = [];
  const dateStrs = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.now() + 3600000 - i * 86400000).toISOString().slice(0, 10);
    dateStrs.push(d);
  }

  const snaps = await dbFire.getAll(...dateStrs.map(d => dbFire.collection('gym_daily_stats').doc(`${GYM}_${d}`)));
  snaps.forEach((snap, i) => {
    if (snap.exists) {
      const data = snap.data();
      stats.push({ gym_id: GYM, date: dateStrs[i], count: data.count || 0, raw_count: data.rawCount || 0 });
    }
  });
  console.log(`✅ ${stats.length} jours de stats récupérés depuis Firestore.`);

  // ── STEP 2: Get Clean Local Register ──────────────────────────────────────
  const rows = dbLocal.prepare(`
    SELECT id, gym_id, date, commercial, nom, tpe, espece, virement, cheque, prix, reste, contrat, abonnement, cin, tel, note_reste, created_at
    FROM register_cache WHERE gym_id = ? AND date >= '2026-04-01' AND date <= '2026-04-30'
  `).all(GYM);
  const totalLocal = rows.reduce((s, r) => s + (Number(r.tpe)||0) + (Number(r.espece)||0) + (Number(r.virement)||0) + (Number(r.cheque)||0), 0);
  console.log(`✅ Registre local : ${rows.length} lignes | Total : ${totalLocal.toLocaleString()} DH`);

  if (totalLocal !== 755700) {
    console.warn(`⚠️  Attention: le total local est de ${totalLocal} DH (Attendu: 755,700). On continue quand même.`);
  }

  // ── STEP 3: Inject Everything to Render ───────────────────────────────────
  console.log('\n🚀 Injection vers Render...');

  // A. Inject Stats (Door Scans)
  const resStats = await post(`${RENDER_BASE}/admin/inject-stats`, { stats }, { 'x-inject-secret': SECRET });
  if (resStats.status === 200) console.log(`   ✅ Stats Scans injectées (${stats.length} jours)`);
  else console.log(`   ❌ Échec Stats : ${resStats.status}`, resStats.body);

  // B. Inject Register (Payments)
  const resReg = await post(`${RENDER_BASE}/admin/inject-register`, { 
    rows, 
    wipe: { gymId: GYM, dateFrom: '2026-04-01', dateTo: '2026-04-30' } 
  }, { 'x-inject-secret': SECRET });
  
  if (resReg.status === 200) {
    console.log(`   ✅ Registre injecté (${rows.length} lignes)`);
    console.log(`   🎯 Nouveau Total Render Dokarat : ${resReg.body.totals?.[0]?.total?.toLocaleString()} DH`);
  } else {
    console.log(`   ❌ Échec Registre : ${resReg.status}`, resReg.body);
  }

  console.log('\n✨ Réparation terminée ! Attendez 30 secondes et rafraîchissez le Dashboard.');
  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
