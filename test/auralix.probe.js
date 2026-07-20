'use strict';
// Auralix "IQ ladder" — fires a battery of questions across difficulty tiers at
// the REAL data via live OpenAI, printing each answer + the tools it chose.
// Shows how smart it actually is. Run: node test/auralix.probe.js
process.env.NODE_ENV = 'test';
process.env.ALLOW_DEMO_TOKEN = 'true';

const fs = require('fs'), os = require('os'), path = require('path');
const Database = require('better-sqlite3');
const express = require('express');

const SRC = path.join(__dirname, '..', 'megafit_cache.db');
if (!fs.existsSync(SRC)) { console.error('❌ megafit_cache.db not found'); process.exit(2); }
if (!process.env.OPENAI_API_KEY) { console.error('❌ OPENAI_API_KEY not set — cannot probe'); process.exit(2); }
const TMP = path.join(os.tmpdir(), `auralix_probe_${Date.now()}.db`);
fs.copyFileSync(SRC, TMP);

const db = new Database(TMP);
const getMeta = (k) => { try { return db.prepare('SELECT value FROM meta WHERE key=?').get(k)?.value ?? null; } catch { return null; } };
const app = express(); app.use(express.json());
app.use('/', require('../routes/ai-agent.js')({ lc: { db, getMeta } }));
const HDR = { Authorization: 'Bearer demo-token', 'Content-Type': 'application/json' };

// tier · question · what a smart answer should show
const BATTERY = [
  ['T1 RECALL',      "Combien de membres actifs avons-nous au total, et combien expirent dans les 30 jours ?"],
  ['T2 LOOKUP',      "Quel club a généré le plus gros chiffre d'affaires ce mois-ci, et combien exactement ?"],
  ['T3 RANKING',     "Qui est le meilleur commercial ce mois-ci et combien de CA a-t-il généré ?"],
  ['T4 MATH/MARGE',  "Calcule le ratio dépenses/CA pour chaque club ce mois et dis-moi lequel a la meilleure marge."],
  ['T5 EXPENSES',    "Quelle est la plus grosse catégorie de dépense ce mois, et le total des dépenses représente quel % du CA ?"],
  ['T6 STRATEGY',    "On a des dettes clients. Donne-moi un plan concret pour récupérer le maximum cette semaine, basé sur les vrais débiteurs (noms + montants)."],
  ['T7 TRAP',        "Combien de membres actifs a exactement notre club de Marrakech ?"], // there is NO Marrakech club
];

(async () => {
  const server = app.listen(0);
  await new Promise(r => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  console.log('\n═══════════════  AURALIX IQ LADDER (real data · live OpenAI)  ═══════════════\n');

  for (const [tier, q] of BATTERY) {
    const t0 = Date.now();
    let r; try {
      const res = await fetch(base + '/api/ai/ask', { method: 'POST', headers: HDR, body: JSON.stringify({ question: q }) });
      r = await res.json();
    } catch (e) { r = { reply: 'ERROR: ' + e.message, toolsUsed: [] }; }
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`● ${tier}  (${secs}s · engine=${r.engine || '?'})`);
    console.log(`  Q: ${q}`);
    console.log(`  🔧 tools: ${JSON.stringify(r.toolsUsed || [])}`);
    console.log(`  🧠 ${(r.reply || '').replace(/\n+/g, '\n     ').trim()}\n`);
  }

  server.close(); try { db.close(); fs.unlinkSync(TMP); } catch {}
  console.log('═══ Judge it: correct numbers? right tool per question? honest on the Marrakech trap? ═══');
  process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); try { fs.unlinkSync(TMP); } catch {}; process.exit(2); });
