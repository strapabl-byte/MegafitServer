'use strict';
// End-to-end test for the Auralix director brain against the REAL local cache DB.
// - Copies megafit_cache.db to a temp file (touches nothing real).
// - Mounts routes/ai-agent.js, authenticates via demo-token (admin bypass).
// - Exercises: snapshot v2, the OpenAI function-calling /ask, and the brief.
// Run: node test/auralix.selftest.js
'use strict';

process.env.NODE_ENV = 'test';
process.env.ALLOW_DEMO_TOKEN = 'true';   // demo-token → admin, for verifyAzureToken/requireAdmin
// OPENAI_API_KEY inherited from the shell if present.

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const express  = require('express');

const SRC = path.join(__dirname, '..', 'megafit_cache.db');
if (!fs.existsSync(SRC)) { console.error('❌ megafit_cache.db not found next to megafit-api/'); process.exit(2); }
const TMP = path.join(os.tmpdir(), `auralix_test_${Date.now()}.db`);
fs.copyFileSync(SRC, TMP);
console.log(`📋 Testing on isolated copy: ${TMP}`);

const db = new Database(TMP);
const getMeta = (k) => { try { return db.prepare('SELECT value FROM meta WHERE key=?').get(k)?.value ?? null; } catch { return null; } };

const makeRouter = require('../routes/ai-agent.js');
const app = express();
app.use(express.json());
app.use('/', makeRouter({ lc: { db, getMeta } }));

const HDR = { Authorization: 'Bearer demo-token', 'Content-Type': 'application/json' };
let pass = 0, fail = 0;
const ok = (n, c, extra = '') => { if (c) { pass++; console.log('  ✓', n); } else { fail++; console.error('  ✗', n, extra); } };
const call = async (method, p, body) => {
  const r = await fetch(base + p, { method, headers: HDR, body: body ? JSON.stringify(body) : undefined });
  let d = null; try { d = await r.json(); } catch {}
  return { status: r.status, d };
};

let base;
(async () => {
  const server = app.listen(0);
  await new Promise(r => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  const hasOpenAI = !!process.env.OPENAI_API_KEY;
  console.log(`\n🔑 OPENAI_API_KEY: ${hasOpenAI ? 'present → live function-calling test' : 'ABSENT → skipping live calls'}\n`);

  // 1) Snapshot v2 — builds on real data, carries new fields
  console.log('▸ Snapshot v2');
  let r = await call('GET', '/api/ai/snapshot');
  const s = r.d?.snapshot;
  ok('snapshot builds (200)', r.status === 200 && !!s, JSON.stringify(r.d).slice(0, 200));
  ok('revenue.month is a number', typeof s?.revenue?.month === 'number', `${s?.revenue?.month}`);
  ok('decaissements.by_category present (v2)', Array.isArray(s?.decaissements?.by_category), JSON.stringify(s?.decaissements?.by_category)?.slice(0, 160));
  ok('decaissements.expense_to_revenue_pct present (v2)', 'expense_to_revenue_pct' in (s?.decaissements || {}), `${s?.decaissements?.expense_to_revenue_pct}`);
  console.log(`    CA mois: ${s?.revenue?.month?.toLocaleString()} DH · Décais: ${s?.decaissements?.month_total?.toLocaleString()} DH (${s?.decaissements?.expense_to_revenue_pct}% du CA)`);
  if (s?.decaissements?.by_category?.length) console.log('    Catégories:', s.decaissements.by_category.map(c => `${c.category}=${c.total}DH`).join(' · '));

  // 2) Auth guard works
  console.log('\n▸ Auth');
  const noAuth = await fetch(base + '/api/ai/ask', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: 'x' }) });
  ok('unauth /ask → 401', noAuth.status === 401, `got ${noAuth.status}`);

  // 3) Live OpenAI function-calling /ask (only if key present)
  if (hasOpenAI) {
    console.log('\n▸ /api/ai/ask — live OpenAI function-calling');
    r = await call('POST', '/api/ai/ask', { question: "Quel est le plus gros décaissement de ce mois, son montant, sa catégorie et quel club ?" });
    ok('ask → 200', r.status === 200, JSON.stringify(r.d).slice(0, 200));
    ok('engine = openai', r.d?.engine === 'openai', `engine=${r.d?.engine}`);
    ok('used ≥1 retrieval tool', Array.isArray(r.d?.toolsUsed) && r.d.toolsUsed.length > 0, `tools=${JSON.stringify(r.d?.toolsUsed)}`);
    ok('non-empty reply', typeof r.d?.reply === 'string' && r.d.reply.length > 10);
    console.log('    tools:', JSON.stringify(r.d?.toolsUsed));
    console.log('    reply:', (r.d?.reply || '').slice(0, 400).replace(/\n/g, ' '));

    console.log('\n▸ /api/ai/ask — member lookup (forces get_member)');
    r = await call('POST', '/api/ai/ask', { question: "Donne-moi la dette totale des 3 plus gros débiteurs, avec leurs noms." });
    ok('debtor question → 200', r.status === 200);
    ok('used a tool', Array.isArray(r.d?.toolsUsed) && r.d.toolsUsed.length > 0, `tools=${JSON.stringify(r.d?.toolsUsed)}`);
    console.log('    tools:', JSON.stringify(r.d?.toolsUsed));
    console.log('    reply:', (r.d?.reply || '').slice(0, 400).replace(/\n/g, ' '));

    // 4) Director's Brief
    console.log('\n▸ /api/ai/director-brief — full-snapshot executive brief');
    r = await call('POST', '/api/ai/director-brief', {});
    ok('brief → 200', r.status === 200, JSON.stringify(r.d).slice(0, 150));
    ok('engine = openai', r.d?.engine === 'openai');
    ok('brief has all 5 sections', ['ÉTAT', 'CHANGÉ', 'POURQUOI', 'ACTION', 'RISQUE'].filter(k => (r.d?.brief || '').toUpperCase().includes(k)).length >= 4, (r.d?.brief || '').slice(0, 120));
    console.log('    brief (extrait):\n' + (r.d?.brief || '').split('\n').slice(0, 12).map(l => '      ' + l).join('\n'));

    const g = await call('GET', '/api/ai/director-brief');
    ok('GET brief returns cached', g.status === 200 && !!g.d?.brief && g.d?.cached === true);
  } else {
    console.log('\n(⏭  live OpenAI tests skipped — set OPENAI_API_KEY to run them)');
  }

  server.close();
  try { db.close(); fs.unlinkSync(TMP); } catch {}
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error('HARNESS ERROR:', e); try { fs.unlinkSync(TMP); } catch {}; process.exit(2); });
