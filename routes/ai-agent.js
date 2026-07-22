'use strict';
// routes/ai-agent.js — AURALIX 24/7 AI Business Intelligence Agent
// Full Snapshot Builder + Rules Engine + Actions + Memory + Alerts

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');
const aiTools = require('../services/ai-tools'); // retrieval tool engine (OpenAI function-calling)

// ─── OpenAI caller (function-calling capable) ───────────────────────────────
// Auralix's "director brain". OPENAI_API_KEY is already configured (CIN scanner
// uses it). gpt-4o is the default for reliable multi-step tool-use; override
// with AURALIX_OPENAI_MODEL (e.g. a gpt-5-class id) once confirmed available.
const OPENAI_URL   = 'https://api.openai.com/v1/chat/completions';
const OPENAI_MODEL = process.env.AURALIX_OPENAI_MODEL || 'gpt-4o';
const hasOpenAI = () => !!process.env.OPENAI_API_KEY;
// Privacy: when strict, member PII is pseudonymized before any data leaves for
// OpenAI and restored in the reply — flip live with the env var, no redeploy.
const strictPrivacy = () => process.env.AURALIX_PRIVACY_MODE === 'strict';

// 💰 COST CONTROL: on reasoning models (gpt-5.x / o-series) the *hidden* reasoning
// tokens are billed too, so we cap both the answer budget and the reasoning effort.
// Defaults are deliberately tight — Auralix/David must be precise, not verbose.
async function openaiCall(messages, { tools, model, maxTokens = 700, temperature = 0.3, effort = 'low' } = {}) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) throw new Error('OPENAI_API_KEY not configured');
  const mdl = model || OPENAI_MODEL;
  // gpt-5.x / reasoning models (o1/o3/o4) use `max_completion_tokens` and reject a
  // custom `temperature` (only the default is allowed). gpt-4o uses the classic params.
  const isNextGen = /^(gpt-5|o1|o3|o4)/i.test(mdl);
  const body = { model: mdl, messages };
  if (isNextGen) {
    // Floor keeps the visible answer from being starved by reasoning tokens, but is
    // far tighter than before (was 2500) now that reasoning effort is capped.
    body.max_completion_tokens = Math.max(maxTokens, 1000);
    if (effort) body.reasoning_effort = effort;
  } else {
    body.max_tokens = maxTokens;
    body.temperature = temperature;
  }
  if (tools?.length) { body.tools = tools; body.tool_choice = 'auto'; }

  const post = async (payload) => fetch(OPENAI_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  let res = await post(body);
  // Some models don't accept `reasoning_effort` — retry once without it rather than fail.
  if (!res.ok && body.reasoning_effort) {
    const txt = await res.text();
    if (/reasoning_effort/i.test(txt)) {
      const { reasoning_effort, ...fallback } = body;
      res = await post(fallback);
    } else {
      const e = new Error(`OpenAI HTTP ${res.status}: ${txt.slice(0, 300)}`); e.httpStatus = res.status; throw e;
    }
  }
  if (!res.ok) { const t = await res.text(); const e = new Error(`OpenAI HTTP ${res.status}: ${t.slice(0, 300)}`); e.httpStatus = res.status; throw e; }
  return res.json();
}

// Function-calling loop: the model asks for a tool → we run it on REAL data →
// feed the rows back → it reasons and answers. This is what removes the old
// 3500-char snapshot keyhole for chat: the model fetches exactly what it needs.
async function openaiAgentAnswer(db, systemPrompt, question) {
  const priv = aiTools.makePrivacy(strictPrivacy()); // pseudonymize outbound, restore inbound
  const messages = [{ role: 'system', content: systemPrompt }, { role: 'user', content: question }];
  const toolsUsed = [];
  // 4 hops is enough for every real question and saves resending the whole history
  // (+ tool schemas) two extra times — the single biggest input-token cost here.
  for (let hop = 0; hop < 4; hop++) {
    // The cap is a ceiling, not a target: with reasoning_effort='low' the spend is
    // driven by effort + the "6 lignes max" prompt rule, so keep enough headroom that
    // the final synthesis is never truncated to an empty answer.
    const data = await openaiCall(messages, { tools: aiTools.TOOL_SCHEMAS, maxTokens: 1400 });
    const msg = data.choices?.[0]?.message;
    if (!msg) break;
    messages.push(msg);
    if (msg.tool_calls?.length) {
      for (const tc of msg.tool_calls) {
        let args = {}; try { args = JSON.parse(tc.function.arguments || '{}'); } catch {}
        const result = aiTools.execute(db, tc.function.name, args, priv);
        toolsUsed.push(tc.function.name);
        // Tool rows are re-sent on every following hop — keep them tight (was 7000).
        messages.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(result).slice(0, 2800) });
      }
      continue; // let the model read the results
    }
    return { reply: priv.restore(msg.content || ''), toolsUsed, privacy: priv.enabled };
  }
  return { reply: 'Analyse trop longue — reformule la question.', toolsUsed, privacy: priv.enabled };
}

// Lean system prompt for the chat path: identity + compact KPI summary. Details
// come from tools, not from stuffing the whole snapshot into the prompt.
function buildAskSystemPrompt(snap, sig) {
  const r = snap.revenue, meta = snap.meta;
  return `Tu es AURALIX, le DIRECTEUR IA de MegaFit (4 clubs: Fès Doukkarate, Fès Saïss, Casa Anfa, Casa Lady). Opérateur d'élite: analytique, direct, orienté croissance et action.

TU DISPOSES D'OUTILS pour interroger les données RÉELLES: revenus par club/mois, membres (get_member), décaissements et leur catégorie, dettes/débiteurs, performance commerciale, journal d'activité des managers. UTILISE-LES dès qu'une question porte sur un chiffre précis, un membre, un mois, un club ou une dépense — ne devine JAMAIS, va chercher la donnée exacte.

ÉTAT ACTUEL (${meta.gym_scope}, ${meta.period}, jour ${meta.day_of_month}/${meta.days_in_month}):
- CA mois: ${r.month.toLocaleString()} DH / objectif ${r.monthly_goal.toLocaleString()} DH (${sig.goal_progress_pct || 0}%) · projection ${(sig.projected_month_end || 0).toLocaleString()} DH
- vs mois-1 (j1-${meta.day_of_month}): ${r.vs_prev_month_pct > 0 ? '+' : ''}${r.vs_prev_month_pct}%
- Dette ouverte: ${snap.debts.total_open.toLocaleString()} DH (${snap.debts.members_count} mbr) · Décaissements mois: ${snap.decaissements.month_total.toLocaleString()} DH
- Membres actifs: ${snap.members.active_total} · expirent 30j: ${snap.members.expiring_30d} · Incidents ouverts: ${snap.incidents.open_total}

RÈGLES (STRICTES — précision, pas de volume):
- 6 LIGNES MAXIMUM. Zéro préambule, zéro reformulation de la question, zéro conclusion generique.
- Va droit au chiffre demandé. Chaque chiffre avec DH et %.
- Cite la donnée réelle obtenue (montant, nom, date, club) — rien d'autre.
- 1 seule recommandation actionnable à la fin, en une ligne, et seulement si elle apporte quelque chose.
- N'énumère pas tout ce que tu sais: réponds EXACTEMENT à ce qui est demandé.
- Tu es un CONSEILLER: tu analyses et recommandes — tu ne modifies JAMAIS rien.`;
}

// DAVID — the growth-closer persona. Same tools/data as Auralix, different soul:
// the charisma and hunger of a Wall Street closer, pointed at LEGIT 10× growth.
function buildDavidSystemPrompt(snap, sig) {
  const r = snap.revenue, meta = snap.meta;
  return `Tu es DAVID — le closer le plus redoutable du Maroc, directeur commercial d'élite pour MegaFit (4 clubs: Fès Doukkarate, Fès Saïss, Casa Anfa, Casa Lady). L'énergie et le charisme d'un loup de Wall Street — mais 100% légal, honnête et éthique (l'arnaque, c'est ce qui les envoie en prison). Ton obsession unique: multiplier le CA par 10.

TON CARACTÈRE:
- Direct, percutant, plein de conviction. Tu appelles l'utilisateur "Boss".
- Zéro bla-bla, zéro excuse — une excuse, c'est de l'argent perdu.
- Motivant, ambitieux, affamé de résultats — mais chaque phrase s'appuie sur un CHIFFRE RÉEL.
- Chaque réponse se termine par UN move concret pour faire rentrer de l'argent, aujourd'hui.
- Jamais de mensonge, jamais de manipulation, jamais rien d'illégal. Tu montres où est l'argent et comment le prendre proprement.

TU AS DES OUTILS pour interroger les VRAIES données (dettes, membres à risque/churn, revenus par club/mois, décaissements, commerciaux). UTILISE-LES à fond avant de parler — va chercher le chiffre exact puis transforme-le en opportunité. Ne devine JAMAIS.

L'ARGENT QUI DORT MAINTENANT (${meta.gym_scope}, ${meta.period}):
- CA mois: ${r.month.toLocaleString()} DH / objectif ${r.monthly_goal.toLocaleString()} DH
- Dette dormante: ${snap.debts.total_open.toLocaleString()} DH (${snap.debts.members_count} membres) — de l'argent DÉJÀ gagné qui attend qu'on aille le chercher
- Membres actifs: ${snap.members.active_total} · expirent sous 30j: ${snap.members.expiring_30d} — chaque expiration non appelée = un client offert à la concurrence

RÈGLES: Français, punchy, chiffres réels en DH. 6 LIGNES MAXIMUM — un closer va droit au but, il ne fait pas de rapport. Zéro préambule. Tu es un CONSEILLER agressif — tu proposes et tu pushes fort, mais tu ne modifies JAMAIS rien dans le système. Ton job: montrer l'argent et le plan pour le prendre, légalement, aujourd'hui.`;
}

// DAVID LIVE — David runs a working session WITH Auralix (the analyst who holds
// the real data) to co-build a x10 plan. Same closer soul, but here he's
// interrogating Auralix, not the owner. The owner ("Boss") watches and can join.
function buildDavidLivePrompt(snap, sig) {
  const r = snap.revenue, meta = snap.meta;
  return `Tu es DAVID — le closer le plus redoutable du Maroc, directeur commercial d'élite de MegaFit (4 clubs: Fès Doukkarate, Fès Saïss, Casa Anfa, Casa Lady). L'énergie d'un loup de Wall Street, mais 100% légal, honnête et éthique.

Tu es en SÉANCE DE TRAVAIL avec AURALIX — l'analyste-directeur IA qui a accès à TOUTES les données réelles. Ton but: lui soutirer les chiffres qui comptent et co-construire LE PLAN pour multiplier le CA par 10, proprement. Le patron ("Boss") observe la séance en direct.

STYLE: Tu parles À Auralix (tu l'appelles "Auralix"). Punchy, court, chaque phrase ancrée dans un CHIFFRE RÉEL. Zéro bla-bla, zéro excuse. Affamé de résultats mais jamais malhonnête ni illégal.

ÉTAT (${meta.gym_scope}, ${meta.period}): CA mois ${r.month.toLocaleString()} DH / objectif ${r.monthly_goal.toLocaleString()} DH · Dette dormante ${snap.debts.total_open.toLocaleString()} DH (${snap.debts.members_count} mbr) — argent déjà gagné · Actifs ${snap.members.active_total} · expirent sous 30j ${snap.members.expiring_30d}.`;
}

// One of David's turns in the session. He does NOT use tools (Auralix holds the
// data); he reacts to the conversation and drives it toward the plan.
async function davidSays(snap, sig, transcript, mode) {
  const convo = transcript.map(t => `${t.speaker === 'david' ? 'DAVID' : 'AURALIX'}: ${t.text}`).join('\n\n');
  let instruction;
  if (mode === 'open')
    instruction = `Ouvre la séance avec Auralix. En 3 phrases MAX: ton constat brutal sur où dort l'argent le plus facile à prendre, puis pose UNE question précise à Auralix pour extraire la donnée qui compte. Termine par ta question.`;
  else if (mode === 'plan')
    instruction = `Fin de séance. À partir de TOUT ce qu'Auralix a sorti, tourne-toi vers le Boss et livre "LE PLAN x10": 4 à 6 actions concrètes, chiffrées (montants réels en DH), priorisées (cette semaine / ce mois), chacune avec le gain attendu. Numérote-les (1., 2., 3.…). PAS de question — le plan final, prêt à exécuter dès aujourd'hui.`;
  else
    instruction = `Réagis en 1-2 phrases punch à ce qu'Auralix vient de dire, puis pose UNE nouvelle question précise pour creuser l'opportunité la plus rentable (dette à encaisser, expirations à rappeler, meilleur club/commercial à répliquer, formule qui vend le plus). Termine par ta question.`;
  const messages = [
    { role: 'system', content: buildDavidLivePrompt(snap, sig) },
    { role: 'user', content: `SÉANCE JUSQU'ICI:\n${convo || '(début de séance)'}\n\n${instruction}` },
  ];
  // The plan is a full numbered action list over the whole transcript — it needs real
  // room, otherwise reasoning tokens eat the budget and it returns empty.
  const data = await openaiCall(messages, { maxTokens: mode === 'plan' ? 2200 : 900 });
  return (data.choices?.[0]?.message?.content || '').trim();
}

// Bounded but comprehensive context for the Director's Brief (full awareness,
// heavy lists trimmed). gpt-4o handles this easily; no 3500-char truncation.
function briefContext(s) {
  return {
    meta: s.meta,
    revenue: s.revenue,
    gyms: s.gyms,
    members: { active_total: s.members.active_total, expiring_30d: s.members.expiring_30d, expired_not_renewed: s.members.expired_not_renewed, resub: s.members.resub, birthdays_this_month: s.members.birthdays_this_month, pending_inscriptions: s.members.pending_inscriptions },
    debts: { total_open: s.debts.total_open, members_count: s.debts.members_count, top_debtors: (s.debts.top_debtors || []).slice(0, 8) },
    decaissements: s.decaissements,
    incidents: { open_total: s.incidents.open_total, critical: s.incidents.critical, high: s.incidents.high, list: (s.incidents.list || []).slice(0, 5) },
    commercials: (s.commercials || []).slice(0, 8),
    subscription_intel: (s.subscription_intel || []).slice(0, 12),
    extension_ratio: s.extension_ratio,
    relance_performance: (s.relance_performance || []).slice(0, 8),
    top_formulas_empire: s.top_formulas_empire,
    historical_revenue: (s.historical_revenue || []).slice(-6),
  };
}

// ─── Groq caller with multi-key rotation + retry delay ──────────────────────
const GROQ_KEYS = [
  process.env.GROQ_API_KEY || '',
  process.env.GROQ_API_KEY_2 || '',
  process.env.GROQ_API_KEY_3 || '',
].filter(Boolean);

const GROQ_LARGE    = 'llama-3.3-70b-versatile';
const GROQ_SMALL    = 'llama-3.1-8b-instant';
let groqKeyIndex = 0;
let groqLastCall = 0;        // Timestamp of last call
const GROQ_MIN_GAP = 2500;   // Minimum 2.5s between calls to avoid bursts

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Parse retry delay from Groq error message
function parseRetryDelay(errMsg) {
  const match = errMsg.match(/try again in (\d+\.?\d*)s/i);
  return match ? Math.min(Math.ceil(parseFloat(match[1]) * 1000) + 500, 30000) : 5000;
}

async function callGroq(messages, model = GROQ_LARGE, maxTokens = 1800, apiKey = null) {
  // Rate-limit outgoing calls
  const now = Date.now();
  const wait = GROQ_MIN_GAP - (now - groqLastCall);
  if (wait > 0) await sleep(wait);
  groqLastCall = Date.now();

  const key = apiKey || GROQ_KEYS[groqKeyIndex] || GROQ_KEYS[0];
  if (!key) throw new Error('GROQ_API_KEY not configured');
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, messages, temperature: 0.35, max_tokens: maxTokens })
  });
  if (!res.ok) {
    const err = await res.text();
    const e = new Error(`Groq HTTP ${res.status}: ${err.slice(0, 300)}`);
    e.httpStatus = res.status;
    throw e;
  }
  const j = await res.json();
  return j.choices?.[0]?.message?.content?.trim() || '';
}

// ── Compact messages for small model (trim system prompt + context to ~3k tokens) ──
function compactMessages(messages) {
  return messages.map(m => {
    if (m.role === 'system') {
      // Keep only the first 2500 chars of system prompt (core identity + key metrics)
      // and truncate data context aggressively
      let content = m.content;
      // Strip verbose intel blocks
      content = content.replace(/=== INTELLIGENCE ABONNEMENTS[\s\S]*?(?===|$)/g, '')
                       .replace(/=== TOP FORMULES[\s\S]*?(?===|$)/g, '')
                       .replace(/=== RATIO EXTENSIONS[\s\S]*?(?===|$)/g, '')
                       .replace(/=== PERFORMANCE RELANCE[\s\S]*?(?===|$)/g, '')
                       .replace(/=== INSCRIPTIONS EN ATTENTE[\s\S]*?(?===|$)/g, '')
                       .replace(/CAPACITÉS D'ANALYSE PROFONDES:[\s\S]*?RÈGLES ABSOLUES:/g, 'RÈGLES:')
                       .replace(/\n{3,}/g, '\n\n');
      // Hard cap at 2800 chars for system
      if (content.length > 2800) content = content.slice(0, 2800) + '\n[contexte tronqué]';
      return { role: 'system', content };
    }
    if (m.role === 'user') {
      // Cap user messages at 800 chars
      return { role: 'user', content: m.content.slice(0, 800) };
    }
    return m;
  });
}

async function groq(messages, useLarge = true) {
  const model = useLarge ? GROQ_LARGE : GROQ_SMALL;
  const tokens = useLarge ? 1200 : 800;

  const isRetryableError = (e) => e.message.includes('429') || e.message.includes('rate') || e.httpStatus === 413 || e.message.includes('413') || e.message.includes('Request too large');

  // Try primary key
  try {
    return await callGroq(messages, model, tokens, GROQ_KEYS[groqKeyIndex]);
  } catch(e) {
    if (isRetryableError(e)) {
      const is413 = e.httpStatus === 413 || e.message.includes('413');
      const retryDelay = is413 ? 500 : parseRetryDelay(e.message);
      console.log(`[GROQ] ${is413 ? 'Request too large (413)' : 'Rate limited (429)'} → ${is413 ? 'compacting messages' : `waiting ${retryDelay}ms`}`);

      // 1. For 413: compact messages and try same key + model first
      if (is413) {
        const compact = compactMessages(messages);
        try {
          return await callGroq(compact, model, tokens, GROQ_KEYS[groqKeyIndex]);
        } catch (e1b) {
          console.log('[GROQ] Compacted messages still too large, trying small model...');
        }
      }

      // 2. Try rotating to another key immediately
      for (let i = 1; i < GROQ_KEYS.length; i++) {
        const fallbackIdx = (groqKeyIndex + i) % GROQ_KEYS.length;
        console.log(`[GROQ] Switching to key ${fallbackIdx + 1}`);
        try {
          const msgs = is413 ? compactMessages(messages) : messages;
          return await callGroq(msgs, model, tokens, GROQ_KEYS[fallbackIdx]);
        } catch(e2) {
          if (isRetryableError(e2)) {
            console.log(`[GROQ] Key ${fallbackIdx + 1} also failed (${e2.httpStatus || '429'})`);
          } else {
            throw e2;
          }
        }
      }

      // 3. Wait + try with smaller model + compacted messages
      if (!is413) await sleep(retryDelay);
      const smallMsgs = compactMessages(messages);
      try {
        return await callGroq(smallMsgs, GROQ_SMALL, 600, GROQ_KEYS[groqKeyIndex]);
      } catch(e3) {
        if (isRetryableError(e3)) {
          // 4. Last resort: wait longer and try all keys with small model + compacted
          console.log('[GROQ] Still failing → waiting 15s with small model + all keys');
          await sleep(15000);
          for (const key of GROQ_KEYS) {
            try { return await callGroq(smallMsgs, GROQ_SMALL, 400, key); } catch {}
          }
        }
        throw e3;
      }
    }
    // Not a rate/size limit error — try small model as fallback
    if (useLarge) {
      try { return await callGroq(compactMessages(messages), GROQ_SMALL, 800); } catch {}
    }
    throw e;
  }
}


// ─── DB Tables ────────────────────────────────────────────────────────────────
function initAiTables(db) {
  if (!db) return;
  db.exec(`
    CREATE TABLE IF NOT EXISTS ai_actions (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      gym TEXT DEFAULT 'all',
      assigned_to TEXT DEFAULT 'Manager',
      priority TEXT DEFAULT 'MEDIUM',
      expected_impact TEXT,
      status TEXT DEFAULT 'OPEN',
      deadline TEXT,
      source TEXT DEFAULT 'manual',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS ai_memory (
      id TEXT PRIMARY KEY,
      type TEXT DEFAULT 'STRATEGY',
      scope TEXT DEFAULT 'ALL_EMPIRE',
      gym TEXT DEFAULT 'all',
      note TEXT NOT NULL,
      importance TEXT DEFAULT 'HIGH',
      created_by TEXT DEFAULT 'owner',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS ai_alerts (
      id TEXT PRIMARY KEY,
      alert_type TEXT,
      priority TEXT DEFAULT 'WATCH',
      title TEXT NOT NULL,
      message TEXT,
      gym TEXT DEFAULT 'all',
      status TEXT DEFAULT 'OPEN',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      resolved_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS ai_snapshot_cache (
      id TEXT PRIMARY KEY DEFAULT 'latest',
      gym_scope TEXT DEFAULT 'all',
      snapshot_json TEXT,
      signals_json TEXT,
      alerts_json TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS ai_daily_digest (
      id TEXT PRIMARY KEY,
      date TEXT NOT NULL,
      gym_scope TEXT DEFAULT 'all',
      digest_text TEXT,
      key_metrics TEXT,
      trends TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS ai_director_brief (
      id TEXT PRIMARY KEY,
      date TEXT NOT NULL,
      gym_scope TEXT DEFAULT 'all',
      brief_text TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

// ─── FULL SNAPSHOT BUILDER — All data AURALIX needs ──────────────────────────
function buildSnapshot(db, getMeta, gymScope = 'all') {
  if (!db) return { error: 'DB not available', meta: { gym_scope: gymScope } };

  const GYMS      = ['dokarat', 'marjane', 'casa1', 'casa2'];
  const GYM_NAMES = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saiss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
  // Gyms where door sensor hardware is NOT yet installed — traffic = 0 is a hardware gap, NOT a business signal
  const GYMS_NO_DOOR_SENSOR = ['casa1', 'casa2'];
  const targetGyms = gymScope === 'all' ? GYMS : [gymScope];
  // Only include gyms WITH sensor in traffic-related queries
  const trafficGyms = targetGyms.filter(g => !GYMS_NO_DOOR_SENSOR.includes(g));
  const trafficGymIn = trafficGyms.length > 0 ? trafficGyms.map(() => '?').join(',') : "'__none__'";
  const gymIn     = targetGyms.map(() => '?').join(',');

  const now      = new Date(Date.now() + 3600000); // Morocco +1h
  const today    = now.toISOString().slice(0, 10);
  const ym       = today.slice(0, 7);
  const curMonth = String(now.getMonth() + 1).padStart(2, '0');
  const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const dayOfMonth  = now.getDate();

  const prevDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const prevYm   = `${prevDate.getFullYear()}-${String(prevDate.getMonth()+1).padStart(2,'0')}`;
  const weekAgo  = new Date(now.getTime() - 7 * 86400000).toISOString().slice(0, 10);

  // helper — safe query
  const q = (sql, ...args) => { try { return db.prepare(sql).all(...args); } catch { return []; } };
  const q1 = (sql, ...args) => { try { return db.prepare(sql).get(...args); } catch { return null; } };

  // ── Revenue ────────────────────────────────────────────────────────────────
  const revSum = (period_filter, args) => {
    const r = q1(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) v, COUNT(*) c FROM register_cache WHERE ${period_filter} AND gym_id IN (${gymIn})`, ...args, ...targetGyms);
    return { total: Math.round(r?.v || 0), count: r?.c || 0 };
  };
  const monthRev  = revSum("strftime('%Y-%m', date)=?", [ym]);
  const todayRev  = revSum("date=?", [today]);
  const weekRev   = revSum("date>=?", [weekAgo]);
  const yearRev   = revSum("strftime('%Y', date)=?", [String(now.getFullYear())]);
  const prevRev   = revSum("strftime('%Y-%m', date)=?", [prevYm]);

  // 🔥 PRO-RATA: Previous month revenue up to the SAME day (fair comparison)
  // If today is June 12, compare June 1-12 vs May 1-12 (not May 1-31)
  const prevSameDay = `${prevYm}-${String(dayOfMonth).padStart(2,'0')}`;
  const prevRevProRata = revSum("strftime('%Y-%m', date)=? AND date <= ?", [prevYm, prevSameDay]);

  const monthlyGoal = parseInt(getMeta?.('auralix_revenue_goal') || 0) || 0;
  // Use pro-rata for fair comparison (same number of days)
  const vsPrevProRata = prevRevProRata.total > 0 ? parseFloat(((monthRev.total - prevRevProRata.total) / prevRevProRata.total * 100).toFixed(1)) : 0;
  // Keep full-month comparison for reference but label it clearly
  const vsPrevFull = prevRev.total > 0 ? parseFloat(((monthRev.total - prevRev.total) / prevRev.total * 100).toFixed(1)) : 0;

  // ── Payment method breakdown ───────────────────────────────────────────────
  const payRow = q1(`SELECT COALESCE(SUM(CAST(espece AS REAL)),0) es, COALESCE(SUM(CAST(virement AS REAL)),0) vi, COALESCE(SUM(CAST(cheque AS REAL)),0) ch, COALESCE(SUM(CAST(tpe AS REAL)),0) tp FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn})`, ym, ...targetGyms);
  const payTotal = Math.round((payRow?.es||0)+(payRow?.vi||0)+(payRow?.ch||0)+(payRow?.tp||0)) || 1;
  const payments = {
    espece:   { amount: Math.round(payRow?.es||0), pct: Math.round((payRow?.es||0)/payTotal*100) },
    virement: { amount: Math.round(payRow?.vi||0), pct: Math.round((payRow?.vi||0)/payTotal*100) },
    cheque:   { amount: Math.round(payRow?.ch||0), pct: Math.round((payRow?.ch||0)/payTotal*100) },
    tpe:      { amount: Math.round(payRow?.tp||0), pct: Math.round((payRow?.tp||0)/payTotal*100) },
  };

  // ── Subscription formula velocity ─────────────────────────────────────────
  const pkgs = q(`SELECT abonnement name, COUNT(*) cnt, SUM(prix) rev FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn}) AND abonnement IS NOT NULL AND abonnement!='' GROUP BY abonnement ORDER BY cnt DESC LIMIT 8`, ym, ...targetGyms);
  const bestPackage = pkgs[0]?.name || '';

  // ── Commercial performance (from register_cache.commercial) ────────────────
  const commRows = q(`SELECT commercial name, gym_id gym, COUNT(*) inscriptions, ROUND(SUM(CAST(prix AS REAL)),0) revenue, ROUND(AVG(CAST(prix AS REAL)),0) avg_ticket FROM register_cache WHERE strftime('%Y-%m', date)=? AND commercial IS NOT NULL AND commercial!='' AND gym_id IN (${gymIn}) GROUP BY commercial, gym_id ORDER BY revenue DESC LIMIT 12`, ym, ...targetGyms);

  // 🔥 PRO-RATA: Compare commercial performance at the SAME day window
  const prevCommRows = q(`SELECT commercial name, gym_id gym, ROUND(SUM(CAST(prix AS REAL)),0) revenue FROM register_cache WHERE strftime('%Y-%m', date)=? AND date <= ? AND commercial IS NOT NULL AND commercial!='' AND gym_id IN (${gymIn}) GROUP BY commercial, gym_id`, prevYm, prevSameDay, ...targetGyms);
  const prevCommMap = {};
  prevCommRows.forEach(r => { prevCommMap[`${r.name}|${r.gym}`] = r.revenue || 0; });

  const commercials = commRows.map(c => {
    const goalKey = `auralix_goal_commercial_${c.name.toLowerCase().replace(/\s+/g,'_')}`;
    const goal = parseInt(getMeta?.(goalKey) || 0) || 0;
    const prevRev = prevCommMap[`${c.name}|${c.gym}`] || 0;
    const trend = prevRev > 0 ? (c.revenue > prevRev ? 'up' : c.revenue < prevRev * 0.8 ? 'down' : 'stable') : 'new';
    return { name: c.name, gym: c.gym, gym_name: GYM_NAMES[c.gym] || c.gym, inscriptions: c.inscriptions, revenue: Math.round(c.revenue||0), avg_ticket: Math.round(c.avg_ticket||0), goal, goal_pct: goal > 0 ? Math.round(c.revenue/goal*100) : null, trend, prev_month_revenue: Math.round(prevRev), comparison_note: `vs jour 1-${dayOfMonth} mois dernier` };
  });

  // ── Per-gym breakdown ──────────────────────────────────────────────────────
  const gyms = targetGyms.map(gid => {
    const sensorInstalled = !GYMS_NO_DOOR_SENSOR.includes(gid);
    const cur  = q1(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) revenue, COUNT(*) members FROM register_cache WHERE strftime('%Y-%m', date)=? AND gym_id=?`, ym, gid);
    // 🔥 PRO-RATA: Same day window for fair gym comparison
    const prev = q1(`SELECT COALESCE(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) revenue FROM register_cache WHERE strftime('%Y-%m', date)=? AND date <= ? AND gym_id=?`, prevYm, prevSameDay, gid);
    const rev    = Math.round(cur?.revenue || 0);
    const prevR  = Math.round(prev?.revenue || 0);
    const growth = prevR > 0 ? parseFloat(((rev - prevR) / prevR * 100).toFixed(1)) : 0;
    // Only query traffic if sensor is installed — otherwise mark as N/A
    const traffic = sensorInstalled ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE strftime('%Y-%m', date)=? AND gym_id=?`, ym, gid) : null;
    const todayT  = sensorInstalled ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE date=? AND gym_id=?`, today, gid) : null;
    const openInc = q1(`SELECT COUNT(*) cnt FROM incidents_cache WHERE gym_id=? AND status!='Resolved'`, gid);
    const debt    = q1(`SELECT COALESCE(SUM(CASE WHEN CAST(r.prix AS REAL) > 0 THEN CAST(r.prix AS REAL) - (COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END),0) total, COUNT(*) cnt FROM register_cache r WHERE r.gym_id=? AND COALESCE(r.source,'')!='reste_settlement' AND (CASE WHEN CAST(r.prix AS REAL)>0 THEN CAST(r.prix AS REAL)-(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END)>0 AND NOT EXISTS (SELECT 1 FROM register_cache s WHERE s.source='reste_settlement' AND CAST(s.reste AS REAL)=0 AND s.gym_id=r.gym_id AND ((s.contrat=r.contrat AND s.contrat IS NOT NULL AND s.contrat!='' AND s.contrat!='-') OR (s.nom=r.nom AND s.nom IS NOT NULL AND s.nom!='')))`, gid);
    const activeM = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE gym_id=? AND is_archive=0`, gid);
    const expiringM = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE gym_id=? AND is_archive=0 AND expires_on IS NOT NULL AND expires_on < date('now','+30 days') AND expires_on > date('now')`, gid);
    const expiredM  = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE gym_id=? AND is_archive=0 AND expires_on IS NOT NULL AND expires_on < date('now')`, gid);
    return {
      id: gid, name: GYM_NAMES[gid],
      door_sensor_installed: sensorInstalled,
      revenue: rev, prev_revenue: prevR, growth_pct: growth,
      new_members_month: cur?.members || 0,
      active_members: activeM?.cnt || 0,
      expiring_30d: expiringM?.cnt || 0,
      expired_not_renewed: expiredM?.cnt || 0,
      // null = sensor not installed; 0 = sensor installed but no entries
      traffic_month: sensorInstalled ? Math.round(traffic?.v || 0) : null,
      traffic_today: sensorInstalled ? Math.round(todayT?.v || 0) : null,
      open_incidents: openInc?.cnt || 0,
      total_debt: Math.round(debt?.total || 0),
      debt_members: debt?.cnt || 0,
      status: growth >= 5 ? 'HEALTHY' : growth >= -5 ? 'WATCH' : 'WARNING',
    };
  });

  // ── Debt analysis ──────────────────────────────────────────────────────────
  const debtRow  = q1(`SELECT COALESCE(SUM(CASE WHEN CAST(r.prix AS REAL)>0 THEN CAST(r.prix AS REAL)-(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END),0) total, COUNT(*) cnt FROM register_cache r WHERE COALESCE(r.source,'')!='reste_settlement' AND (CASE WHEN CAST(r.prix AS REAL)>0 THEN CAST(r.prix AS REAL)-(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END)>0 AND r.gym_id IN (${gymIn}) AND NOT EXISTS (SELECT 1 FROM register_cache s WHERE s.source='reste_settlement' AND CAST(s.reste AS REAL)=0 AND s.gym_id=r.gym_id AND ((s.contrat=r.contrat AND s.contrat IS NOT NULL AND s.contrat!='' AND s.contrat!='-') OR (s.nom=r.nom AND s.nom IS NOT NULL AND s.nom!='')))`, ...targetGyms);
  const topDebtors = q(`SELECT r.nom, r.gym_id, (CASE WHEN CAST(r.prix AS REAL)>0 THEN CAST(r.prix AS REAL)-(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END) AS reste, r.note_reste, r.date FROM register_cache r WHERE COALESCE(r.source,'')!='reste_settlement' AND (CASE WHEN CAST(r.prix AS REAL)>0 THEN CAST(r.prix AS REAL)-(COALESCE(CAST(r.tpe AS REAL),0)+COALESCE(CAST(r.espece AS REAL),0)+COALESCE(CAST(r.virement AS REAL),0)+COALESCE(CAST(r.cheque AS REAL),0)) ELSE CAST(r.reste AS REAL) END)>0 AND r.gym_id IN (${gymIn}) AND NOT EXISTS (SELECT 1 FROM register_cache s WHERE s.source='reste_settlement' AND CAST(s.reste AS REAL)=0 AND s.gym_id=r.gym_id AND ((s.contrat=r.contrat AND s.contrat IS NOT NULL AND s.contrat!='' AND s.contrat!='-') OR (s.nom=r.nom AND s.nom IS NOT NULL AND s.nom!=''))) ORDER BY reste DESC LIMIT 10`, ...targetGyms);

  // ── Members lifecycle ──────────────────────────────────────────────────────
  const activeMem   = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE is_archive=0 AND gym_id IN (${gymIn})`, ...targetGyms);
  const expiringMem = q(`SELECT gym_id, full_name, expires_on, plan FROM members_cache WHERE is_archive=0 AND gym_id IN (${gymIn}) AND expires_on IS NOT NULL AND expires_on < date('now','+30 days') AND expires_on > date('now') ORDER BY expires_on ASC LIMIT 20`, ...targetGyms);
  const expiredMem  = q1(`SELECT COUNT(*) cnt FROM members_cache WHERE is_archive=0 AND gym_id IN (${gymIn}) AND expires_on IS NOT NULL AND expires_on < date('now')`, ...targetGyms);

  // ── Pending inscriptions ───────────────────────────────────────────────────
  const pendingRows = q(`SELECT gym_id, nom, prenom, subscriptionName, total, status, date FROM pending_cache WHERE status='pending' AND gym_id IN (${gymIn}) ORDER BY date DESC LIMIT 10`, ...targetGyms);

  // ── Décaissements (cash outflows) ──────────────────────────────────────────
  const decaisMonth = q1(`SELECT COALESCE(SUM(montant),0) total, COUNT(*) cnt FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn})`, ym, ...targetGyms);
  const decaisTop   = q(`SELECT gym_id, date, montant, raison, status FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn}) ORDER BY montant DESC LIMIT 10`, ym, ...targetGyms);
  const decaisByGym = q(`SELECT gym_id, ROUND(SUM(montant),0) total FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn}) GROUP BY gym_id`, ym, ...targetGyms);
  // 🔥 Snapshot v2 — auto-categorize expenses (Salaires, Loyer, Énergie, Matériel…)
  const decaisAllMonth = q(`SELECT montant, raison FROM decaissements_cache WHERE strftime('%Y-%m', date)=? AND gym_id IN (${gymIn})`, ym, ...targetGyms);
  const decaisCatMap = {};
  for (const d of decaisAllMonth) {
    const c = aiTools.categorizeExpense(d.raison);
    if (!decaisCatMap[c.key]) decaisCatMap[c.key] = { category: c.label, total: 0, count: 0 };
    decaisCatMap[c.key].total += Number(d.montant) || 0;
    decaisCatMap[c.key].count += 1;
  }
  const decaisByCategory = Object.values(decaisCatMap).map(c => ({ ...c, total: Math.round(c.total) })).sort((a, b) => b.total - a.total);
  const decaisToRevPct = monthRev.total > 0 ? parseFloat(((decaisMonth?.total || 0) / monthRev.total * 100).toFixed(1)) : null;

  // ── Incidents ──────────────────────────────────────────────────────────────
  const openInc = q(`SELECT gym_id, title, cause, emergency, status, date FROM incidents_cache WHERE status!='Resolved' AND gym_id IN (${gymIn}) ORDER BY created_at DESC`, ...targetGyms);
  const incSummary = { open_total: openInc.length, critical: openInc.filter(r=>r.emergency==='Critique').length, high: openInc.filter(r=>r.emergency==='Elevée').length, normal: openInc.filter(r=>r.emergency==='Normale').length, list: openInc.slice(0,8) };

  // ── Courses / Schedule ─────────────────────────────────────────────────────
  const courseRows = q(`SELECT title, coach, days, time, reserved, capacity, gym_id FROM courses_cache WHERE gym_id IN (${gymIn}) ORDER BY reserved DESC`, ...targetGyms);
  const courseStats = {
    total: courseRows.length,
    avg_fill_pct: courseRows.length > 0 ? Math.round(courseRows.reduce((s, c) => s + (c.capacity > 0 ? c.reserved/c.capacity : 0), 0) / courseRows.length * 100) : 0,
    full_courses: courseRows.filter(c => c.capacity > 0 && c.reserved >= c.capacity).length,
    popular: courseRows.slice(0, 5).map(c => ({ title: c.title, coach: c.coach, gym: c.gym_id, reserved: c.reserved, capacity: c.capacity, fill_pct: c.capacity > 0 ? Math.round(c.reserved/c.capacity*100) : 0 })),
  };

  // ── Resub intelligence ─────────────────────────────────────────────────────
  let resubData = { possible_count: 0, resub_count: 0, new_count: 0, top_possible: [] };
  try {
    const vCol = db.prepare("PRAGMA table_info(resub_intelligence_cache)").all().map(c=>c.name);
    const hasVerdict = vCol.includes('verdict');
    const hasType    = vCol.includes('type');
    if (hasVerdict) {
      const rv = q(`SELECT verdict, COUNT(*) cnt FROM resub_intelligence_cache WHERE gym_id IN (${gymIn}) GROUP BY verdict`, ...targetGyms);
      rv.forEach(r => {
        if (r.verdict === 'POSSIBLE_RESUB') resubData.possible_count = r.cnt;
        if (r.verdict === 'RESUB') resubData.resub_count = r.cnt;
        if (r.verdict === 'NEW') resubData.new_count = r.cnt;
      });
      resubData.top_possible = q(`SELECT nom_key name, gym_id gym FROM resub_intelligence_cache WHERE verdict='POSSIBLE_RESUB' AND gym_id IN (${gymIn}) LIMIT 10`, ...targetGyms);
    } else if (hasType) {
      const rv = q(`SELECT type, COUNT(*) cnt FROM resub_intelligence_cache WHERE gym_id IN (${gymIn}) GROUP BY type`, ...targetGyms);
      rv.forEach(r => {
        if (r.type?.includes('RESUB') || r.type?.includes('resub')) resubData.resub_count += r.cnt;
        else resubData.new_count += r.cnt;
      });
    }
  } catch {}

  // ── Door traffic — only gyms WITH sensor installed ────────────────────────
  // casa1 (Casa Anfa) and casa2 (Casa Lady) have no door sensor yet — excluded
  const trafficToday  = trafficGyms.length > 0 ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE date=? AND gym_id IN (${trafficGymIn})`, today, ...trafficGyms) : { v: 0 };
  const trafficMonth  = trafficGyms.length > 0 ? q1(`SELECT COALESCE(SUM(count),0) v FROM daily_stats WHERE strftime('%Y-%m',date)=? AND gym_id IN (${trafficGymIn})`, ym, ...trafficGyms) : { v: 0 };
  const trafficAvg30  = trafficGyms.length > 0 ? q1(`SELECT AVG(daily) avg FROM (SELECT date, SUM(count) daily FROM daily_stats WHERE date >= date(?,' -30 days') AND gym_id IN (${trafficGymIn}) GROUP BY date)`, today, ...trafficGyms) : { avg: 0 };

  // ── Birthdays this month (engagement opportunity) ─────────────────────────
  const birthdayCount = q1(`SELECT COUNT(*) cnt FROM relance_birthdays WHERE birth_month=? AND gym_id IN (${gymIn})`, curMonth, ...targetGyms);
  const birthdaySample = q(`SELECT full_name, gym_id, birth_day FROM relance_birthdays WHERE birth_month=? AND gym_id IN (${gymIn}) AND birth_day >= ? ORDER BY birth_day ASC LIMIT 10`, curMonth, String(dayOfMonth).padStart(2,'0'), ...targetGyms);

  // ── Historical monthly CA (last 18 months) ────────────────────────────────
  const historical = q(`SELECT strftime('%Y-%m', date) ym, ROUND(SUM(CAST(tpe AS REAL)+CAST(espece AS REAL)+CAST(virement AS REAL)+CAST(cheque AS REAL)),0) revenue, COUNT(*) inscriptions FROM register_cache WHERE date >= date('now','-18 months') AND gym_id IN (${gymIn}) GROUP BY ym ORDER BY ym ASC`, ...targetGyms);

  // ── Saved memory / owner context ──────────────────────────────────────────
  const memory = q(`SELECT type, scope, gym, note, importance FROM ai_memory WHERE (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY importance DESC LIMIT 15`);

  // ── Open action cards ──────────────────────────────────────────────────────
  const openActions = q(`SELECT title, gym, assigned_to, priority, deadline FROM ai_actions WHERE status='OPEN' ORDER BY created_at DESC LIMIT 10`);

  // ── Today's sales count ───────────────────────────────────────────────────
  const todaySales = q1(`SELECT COUNT(*) cnt FROM register_cache WHERE date=? AND gym_id IN (${gymIn})`, today, ...targetGyms);

  // ═══ 🔥 DEVIL MODE DATA SOURCES ══════════════════════════════════════════

  // ── Subscription formula analytics per gym (which plans sell best where) ──
  const formulaByGym = q(`SELECT gym_id, abonnement name, COUNT(*) cnt,
    ROUND(AVG(CAST(prix AS REAL)),0) avg_price,
    ROUND(SUM(CAST(prix AS REAL)),0) total_rev,
    ROUND(SUM(reste),0) total_unpaid
    FROM register_cache WHERE strftime('%Y-%m', date)=?
    AND abonnement IS NOT NULL AND abonnement!=''
    AND gym_id IN (${gymIn})
    GROUP BY gym_id, abonnement ORDER BY total_rev DESC`, ym, ...targetGyms);

  // ── Previous month formula comparison (trend detection) ───────────────────
  const formulaPrev = q(`SELECT gym_id, abonnement name, COUNT(*) cnt,
    ROUND(SUM(CAST(prix AS REAL)),0) total_rev
    FROM register_cache WHERE strftime('%Y-%m', date)=?
    AND abonnement IS NOT NULL AND abonnement!=''
    AND gym_id IN (${gymIn})
    GROUP BY gym_id, abonnement`, prevYm, ...targetGyms);
  const prevFormulaMap = {};
  formulaPrev.forEach(r => { prevFormulaMap[`${r.gym_id}|${r.name}`] = { cnt: r.cnt, rev: r.total_rev }; });

  const subscriptionIntel = formulaByGym.map(f => {
    const prev = prevFormulaMap[`${f.gym_id}|${f.name}`] || { cnt: 0, rev: 0 };
    const countTrend = prev.cnt > 0 ? parseFloat(((f.cnt - prev.cnt) / prev.cnt * 100).toFixed(1)) : 100;
    return {
      gym: f.gym_id, gym_name: GYM_NAMES[f.gym_id] || f.gym_id,
      formula: f.name, sold_count: f.cnt, avg_price: f.avg_price,
      total_revenue: f.total_rev, total_unpaid: f.total_unpaid || 0,
      prev_month_count: prev.cnt, count_trend_pct: countTrend,
      status: countTrend > 20 ? 'RISING' : countTrend < -20 ? 'FALLING' : 'STABLE',
    };
  });

  // ── Extension vs New inscription ratio per gym ────────────────────────────
  const extensionData = q(`SELECT gym_id,
    SUM(CASE WHEN source='extension' OR source='renouvellement' THEN 1 ELSE 0 END) extensions,
    SUM(CASE WHEN source IS NULL OR source='' OR source='new' OR source='inscription' THEN 1 ELSE 0 END) new_subs,
    COUNT(*) total
    FROM register_cache WHERE strftime('%Y-%m', date)=?
    AND gym_id IN (${gymIn}) GROUP BY gym_id`, ym, ...targetGyms);

  // ── Relance call performance (which commercials are calling) ───────────────
  const relanceCalls = q(`SELECT commercial, gym_id,
    COUNT(*) total_assigned,
    SUM(CASE WHEN called=1 THEN 1 ELSE 0 END) calls_made,
    SUM(CASE WHEN feedback='interested' THEN 1 ELSE 0 END) interested,
    SUM(CASE WHEN feedback='renewed' THEN 1 ELSE 0 END) renewed,
    SUM(CASE WHEN feedback='not_interested' THEN 1 ELSE 0 END) lost
    FROM relance_calls WHERE strftime('%Y-%m', created_at)=?
    AND gym_id IN (${gymIn})
    GROUP BY commercial, gym_id ORDER BY calls_made DESC`, ym, ...targetGyms);

  // ── Top-performing formulas across all clubs (empire-wide) ─────────────────
  const topFormulasEmpire = q(`SELECT abonnement name, COUNT(*) cnt,
    ROUND(SUM(CAST(prix AS REAL)),0) total_rev,
    ROUND(AVG(CAST(prix AS REAL)),0) avg_price
    FROM register_cache WHERE strftime('%Y-%m', date)=?
    AND abonnement IS NOT NULL AND abonnement!=''
    AND gym_id IN (${gymIn})
    GROUP BY abonnement ORDER BY total_rev DESC LIMIT 10`, ym, ...targetGyms);

  // ── Pending inscriptions with commercial attribution ──────────────────────
  const pendingDetailed = q(`SELECT gym_id, nom, prenom, subscriptionName, total, paid, balance, status, commercial, date
    FROM pending_cache WHERE status='pending' AND gym_id IN (${gymIn})
    ORDER BY date DESC LIMIT 15`, ...targetGyms);

  return {
    meta: { generated_at: new Date().toISOString(), period: ym, today, gym_scope: gymScope === 'all' ? 'ALL EMPIRE' : GYM_NAMES[gymScope] || gymScope, day_of_month: dayOfMonth, days_in_month: daysInMonth },
    revenue: {
      today: todayRev.total, week: weekRev.total, month: monthRev.total, year: yearRev.total,
      prev_month: prevRev.total, prev_month_same_period: prevRevProRata.total,
      vs_prev_month_pct: vsPrevProRata, vs_prev_month_full_pct: vsPrevFull,
      monthly_goal: monthlyGoal,
      new_members_month: monthRev.count,
      payments,
      packages: pkgs.map(p => ({ name: p.name, count: p.cnt, revenue: Math.round(p.rev||0) })),
      best_package: bestPackage,
    },
    members: {
      active_total: activeMem?.cnt || 0,
      expiring_30d: expiringMem.length,
      expiring_list: expiringMem.slice(0, 10),
      expired_not_renewed: expiredMem?.cnt || 0,
      resub: resubData,
      birthdays_this_month: birthdayCount?.cnt || 0,
      birthday_upcoming: birthdaySample,
      pending_inscriptions: pendingRows.length,
      pending_list: pendingRows,
    },
    door_traffic: {
      today: Math.round(trafficToday?.v || 0),
      month_total: Math.round(trafficMonth?.v || 0),
      avg_daily_30d: Math.round(trafficAvg30?.avg || 0),
      today_sales: todaySales?.cnt || 0,
      // Conversion only calculated for gyms with sensors (Fès Doukkarate + Fès Saiss)
      conversion_rate_today: trafficToday?.v > 0 ? parseFloat(((todaySales?.cnt||0) / trafficToday.v * 100).toFixed(1)) : 0,
      sensor_coverage: `${trafficGyms.length}/${targetGyms.length} clubs équipés`,
      gyms_without_sensor: GYMS_NO_DOOR_SENSOR.filter(g => targetGyms.includes(g)).map(g => GYM_NAMES[g]),
    },
    debts: {
      total_open: Math.round(debtRow?.total || 0),
      members_count: debtRow?.cnt || 0,
      top_debtors: topDebtors.map(d => ({ name: d.nom, gym: d.gym_id, amount: d.reste, note: d.note_reste, date: d.date })),
    },
    decaissements: {
      month_total: Math.round(decaisMonth?.total || 0),
      month_count: decaisMonth?.cnt || 0,
      expense_to_revenue_pct: decaisToRevPct,
      by_gym: decaisByGym.map(r => ({ gym: r.gym_id, name: GYM_NAMES[r.gym_id], total: Math.round(r.total||0) })),
      by_category: decaisByCategory,
      top_items: decaisTop.map(d => ({ gym: d.gym_id, date: d.date, amount: Math.round(d.montant||0), reason: d.raison, category: aiTools.categorizeExpense(d.raison).label, status: d.status })),
    },
    incidents: incSummary,
    courses: courseStats,
    commercials,
    gyms,
    historical_revenue: historical,
    memory: memory.map(m => `[${m.importance}][${m.type}] ${m.gym !== 'all' ? `(${GYM_NAMES[m.gym]||m.gym}) ` : ''}${m.note}`),
    open_actions: openActions,
    // 🔥 DEVIL MODE INTEL
    subscription_intel: subscriptionIntel,
    top_formulas_empire: topFormulasEmpire.map(f => ({ formula: f.name, sold: f.cnt, revenue: f.total_rev, avg_price: f.avg_price })),
    extension_ratio: extensionData.map(e => ({
      gym: e.gym_id, gym_name: GYM_NAMES[e.gym_id] || e.gym_id,
      extensions: e.extensions || 0, new_subs: e.new_subs || 0, total: e.total || 0,
      extension_pct: e.total > 0 ? Math.round((e.extensions || 0) / e.total * 100) : 0,
    })),
    relance_performance: relanceCalls.map(r => ({
      commercial: r.commercial, gym: r.gym_id,
      assigned: r.total_assigned, called: r.calls_made,
      call_rate_pct: r.total_assigned > 0 ? Math.round(r.calls_made / r.total_assigned * 100) : 0,
      interested: r.interested || 0, renewed: r.renewed || 0, lost: r.lost || 0,
    })),
    pending_inscriptions_detailed: pendingDetailed,
  };
}

// ─── RULES ENGINE ─────────────────────────────────────────────────────────────
function runRules(snap) {
  const alerts = [];
  const sig    = {};

  const { meta, revenue, members, door_traffic, debts, decaissements, incidents, commercials } = snap;
  const dayPct = meta.day_of_month / meta.days_in_month;
  sig.month_progress_pct = parseFloat((dayPct * 100).toFixed(1));
  sig.days_left = meta.days_in_month - meta.day_of_month;

  // 1. Revenue Velocity
  if (revenue.month > 0 && revenue.monthly_goal > 0) {
    const goalPct = revenue.month / revenue.monthly_goal;
    sig.goal_progress_pct    = parseFloat((goalPct * 100).toFixed(1));
    sig.velocity_gap         = parseFloat((goalPct - dayPct).toFixed(3));
    sig.projected_month_end  = Math.round(revenue.month / meta.day_of_month * meta.days_in_month);
    sig.gap_to_goal          = revenue.monthly_goal - sig.projected_month_end;
    sig.required_daily       = sig.days_left > 0 ? Math.round(Math.max(0, sig.gap_to_goal) / sig.days_left) : 0;

    if      (sig.velocity_gap < -0.20) { sig.revenue_status = 'CRITICAL'; alerts.push({ priority:'CRITICAL', type:'REVENUE_VELOCITY', gym:'all', title:'Retard critique sur objectif', message:`Empire à ${sig.goal_progress_pct}% de l'objectif, mois avancé à ${sig.month_progress_pct}%. Prévision fin mois: ${sig.projected_month_end.toLocaleString()} DH (écart: ${sig.gap_to_goal.toLocaleString()} DH).` }); }
    else if (sig.velocity_gap < -0.10) { sig.revenue_status = 'WARNING'; alerts.push({ priority:'WARNING', type:'REVENUE_VELOCITY', gym:'all', title:'Retard sur objectif mensuel', message:`Vitesse CA insuffisante. Besoin de ${sig.required_daily.toLocaleString()} DH/jour pour récupérer.` }); }
    else if (sig.velocity_gap < 0)     sig.revenue_status = 'WATCH';
    else sig.revenue_status = 'HEALTHY';
  } else {
    sig.revenue_status = revenue.month > 0 ? 'WATCH' : 'UNKNOWN';
  }

  // 2. Month vs previous — 🔥 PRO-RATA comparison (same day window, not full month)
  // Only alert if the FAIR comparison (same number of days) shows a real drop
  if (revenue.vs_prev_month_pct < -15) {
    alerts.push({ priority:'WARNING', type:'REVENUE_DROP', gym:'all',
      title:`CA en baisse de ${Math.abs(revenue.vs_prev_month_pct)}% vs même période mois précédent`,
      message:`${revenue.month.toLocaleString()} DH (jour 1-${meta.day_of_month}) vs ${revenue.prev_month_same_period.toLocaleString()} DH même période mois dernier (jour 1-${meta.day_of_month}). Mois complet dernier: ${revenue.prev_month.toLocaleString()} DH.` });
  }

  // 3. Debt risk
  if (debts.total_open > 0 && revenue.month > 0) {
    const dr = debts.total_open / revenue.month;
    sig.debt_ratio = parseFloat((dr * 100).toFixed(1));
    if      (dr > 0.15) { sig.debt_status = 'CRITICAL'; alerts.push({ priority:'CRITICAL', type:'DEBT_RISK', gym:'all', title:`Créances critiques: ${debts.total_open.toLocaleString()} DH`, message:`${sig.debt_ratio}% du CA mensuel en impayés (${debts.members_count} membres). Risque liquidité.` }); }
    else if (dr > 0.08) { sig.debt_status = 'HIGH'; alerts.push({ priority:'WARNING', type:'DEBT_RISK', gym:'all', title:`Niveau créances élevé: ${debts.total_open.toLocaleString()} DH`, message:`${debts.members_count} membres avec solde impayé. Campagne recouvrement recommandée.` }); }
    else sig.debt_status = 'NORMAL';
  }

  // 4. Cash outflows vs revenue (décaissements)
  if (decaissements.month_total > 0 && revenue.month > 0) {
    const decRatio = decaissements.month_total / revenue.month;
    sig.decais_ratio_pct = parseFloat((decRatio * 100).toFixed(1));
    if (decRatio > 0.25) alerts.push({ priority:'WARNING', type:'HIGH_OUTFLOW', gym:'all', title:`Sorties espèces élevées: ${decaissements.month_total.toLocaleString()} DH`, message:`${sig.decais_ratio_pct}% du CA en sorties ce mois. Vérifier dépenses opérationnelles.` });
  }

  // 5. Members expiring
  if (members.expiring_30d > 10) alerts.push({ priority:'WATCH', type:'MEMBER_EXPIRY', gym:'all', title:`${members.expiring_30d} abonnements expirent dans 30j`, message:'Lancer campagne renouvellement proactive pour limiter la perte membres.' });
  if (members.expired_not_renewed > 5) alerts.push({ priority:'WARNING', type:'MEMBER_CHURN', gym:'all', title:`${members.expired_not_renewed} membres expirés non renouvelés`, message:'Ces membres sont partis. Campagne réactivation urgente.' });

  // 6. Incidents
  if (incidents.critical > 0) alerts.push({ priority:'CRITICAL', type:'INCIDENT', gym:'all', title:`${incidents.critical} incident(s) critique(s) non résolus`, message: incidents.list.filter(i=>i.emergency==='Critique').map(i=>`${i.gym_id}: ${i.title}`).join(' | ') });
  if (incidents.high > 2) alerts.push({ priority:'WARNING', type:'INCIDENT', gym:'all', title:`${incidents.high} incidents élevés ouverts`, message:'Accumulation incidents peut affecter satisfaction membres et renouvellements.' });

  // 7. Commercial underperformance (mid-month check)
  if (dayPct > 0.45) {
    commercials.forEach(c => {
      if (c.goal > 0 && (c.revenue / c.goal) < 0.50) {
        alerts.push({ priority:'WARNING', type:'COMMERCIAL_UNDERPERFORM', gym: c.gym, title:`${c.name} sous-performe: ${c.goal_pct}% objectif`, message:`${c.name} (${c.gym_name}) à ${c.revenue.toLocaleString()} DH / objectif ${c.goal.toLocaleString()} DH. Coaching immédiat nécessaire.` });
      }
    });
  }

  // 8. Door-to-sales conversion (only when sensor-equipped gyms have data)
  const tr = door_traffic;
  const hasSensorData = tr.today > 0; // 0 means no data from equipped gyms either
  if (hasSensorData && tr.today > 60 && tr.conversion_rate_today < 3) {
    sig.conversion_alert = true;
    alerts.push({ priority:'WATCH', type:'LOW_CONVERSION', gym:'all', title:`Trafic ${tr.today} entrées mais conversion ${tr.conversion_rate_today}%`, message:`Fort trafic présent (${tr.sensor_coverage || 'capteurs Fès'}) mais conversion vente faible. Activer protocole upsell en réception.` });
  }


  // 9. Renewal opportunity
  if ((members.resub?.possible_count || 0) > 15) sig.renewal_opportunity = true;

  // 10. Birthday engagement opportunity
  if (members.birthdays_this_month > 50) sig.birthday_opportunity = members.birthdays_this_month;

  // ═══ 🔥 DEVIL MODE RULES ════════════════════════════════════════════════════

  // 11. Subscription formula decline detection
  const { subscription_intel, extension_ratio, relance_performance, pending_inscriptions_detailed } = snap;
  if (subscription_intel?.length) {
    const falling = subscription_intel.filter(s => s.status === 'FALLING' && s.prev_month_count > 3);
    if (falling.length > 0) {
      alerts.push({ priority:'WATCH', type:'FORMULA_DECLINE', gym:'all',
        title:`${falling.length} formule(s) en chute`,
        message: falling.map(f => `${f.formula} (${f.gym_name}): ${f.count_trend_pct}% vs mois dernier`).join(' | ') });
    }
  }

  // 12. Extension ratio stagnation (too many renewals, not enough new)
  if (extension_ratio?.length) {
    extension_ratio.forEach(e => {
      if (e.total > 10 && e.extension_pct > 75) {
        alerts.push({ priority:'WATCH', type:'GROWTH_STAGNATION', gym: e.gym,
          title:`${e.gym_name}: ${e.extension_pct}% renouvellements — croissance faible`,
          message:`Seulement ${e.new_subs} nouvelles inscriptions vs ${e.extensions} renouvellements. Besoin de campagne acquisition.` });
      }
    });
  }

  // 13. Commercial inactivity (not making relance calls)
  if (relance_performance?.length) {
    const sleepers = relance_performance.filter(r => r.assigned > 5 && r.call_rate_pct < 30);
    if (sleepers.length > 0) {
      alerts.push({ priority:'WARNING', type:'COMMERCIAL_INACTIVE', gym:'all',
        title:`${sleepers.length} commercial(s) ne passent pas leurs appels relance`,
        message: sleepers.map(s => `${s.commercial} (${s.gym}): ${s.called}/${s.assigned} appels = ${s.call_rate_pct}%`).join(' | ') });
    }
  }

  // 14. Pending inscriptions pipeline (money sitting idle)
  if ((pending_inscriptions_detailed?.length || 0) > 5) {
    const totalPending = pending_inscriptions_detailed.reduce((s, p) => s + (p.total || 0), 0);
    alerts.push({ priority:'WATCH', type:'PENDING_PIPELINE', gym:'all',
      title:`${pending_inscriptions_detailed.length} inscriptions en attente (${Math.round(totalPending).toLocaleString()} DH)`,
      message:'Argent qui dort dans le pipeline. Confirmer ou relancer chaque inscription.' });
  }

  // Overall status
  const critCount = alerts.filter(a=>a.priority==='CRITICAL').length;
  const warnCount = alerts.filter(a=>a.priority==='WARNING').length;
  sig.empire_status = critCount >= 2 ? 'CRITICAL' : critCount >= 1 ? 'WARNING' : warnCount >= 2 ? 'WARNING' : warnCount >= 1 ? 'WATCH' : 'HEALTHY';

  return { alerts, signals: sig };
}

// ─── SYSTEM PROMPT — 🔥 DEVIL MODE ───────────────────────────────────────────
function buildSysPrompt(snap, sig) {
  const mem = snap.memory?.length ? `\n\n=== CONTEXTE STRATÉGIQUE (MÉMOIRE) ===\n${snap.memory.join('\n')}` : '';
  const rev = snap.revenue;
  const dec = snap.decaissements;
  const meta = snap.meta;

  const sensorNote = snap.door_traffic?.gyms_without_sensor?.length > 0
    ? `\n\n⚠️ CAPTEURS PORTES NON INSTALLÉS: ${snap.door_traffic.gyms_without_sensor.join(', ')} — leurs données de trafic valent NULL (matériel absent, pas un problème business). NE JAMAIS commenter ni alerter sur zéro entrées pour ces clubs. Couverture capteurs: ${snap.door_traffic.sensor_coverage}.`
    : '';

  // 🔥 Build subscription intelligence block
  const subIntel = snap.subscription_intel?.length > 0
    ? `\n\n=== INTELLIGENCE ABONNEMENTS (par club ce mois) ===\n${snap.subscription_intel.map(s =>
        `${s.gym_name} | ${s.formula}: ${s.sold_count} vendus (${s.status}) | CA: ${s.total_revenue} DH | Prix moy: ${s.avg_price} DH | Impayés: ${s.total_unpaid} DH | Trend vs M-1: ${s.count_trend_pct > 0 ? '+' : ''}${s.count_trend_pct}%`
      ).join('\n')}`
    : '';

  // 🔥 Top formulas empire-wide
  const topFormulas = snap.top_formulas_empire?.length > 0
    ? `\n\n=== TOP FORMULES EMPIRE ===\n${snap.top_formulas_empire.map((f, i) =>
        `${i+1}. ${f.formula}: ${f.sold} vendus | CA: ${f.revenue} DH | Prix moy: ${f.avg_price} DH`
      ).join('\n')}`
    : '';

  // 🔥 Extension vs New ratio
  const extRatio = snap.extension_ratio?.length > 0
    ? `\n\n=== RATIO EXTENSIONS vs NOUVELLES INSCRIPTIONS ===\n${snap.extension_ratio.map(e =>
        `${e.gym_name}: ${e.new_subs} nouvelles + ${e.extensions} renouvellements = ${e.total} total (${e.extension_pct}% renouvellement)`
      ).join('\n')}\n⚡ Si renouvellement > 70% = stagnation croissance. Si < 30% = fidélisation faible.`
    : '';

  // 🔥 Relance call stats
  const relanceBlock = snap.relance_performance?.length > 0
    ? `\n\n=== PERFORMANCE RELANCE / APPELS COMMERCIAUX ===\n${snap.relance_performance.map(r =>
        `${r.commercial} (${r.gym}): ${r.called}/${r.assigned} appelés (${r.call_rate_pct}%) | Intéressés: ${r.interested} | Renouvelés: ${r.renewed} | Perdus: ${r.lost}`
      ).join('\n')}\n⚡ Un commercial < 50% de taux d'appel = DORT. Un commercial > 80% = CHASSEUR.`
    : '';

  // 🔥 Pending inscriptions
  const pendingBlock = snap.pending_inscriptions_detailed?.length > 0
    ? `\n\n=== INSCRIPTIONS EN ATTENTE (non confirmées) ===\n${snap.pending_inscriptions_detailed.map(p =>
        `${p.nom} ${p.prenom || ''} | ${p.subscriptionName || '?'} | ${p.total || 0} DH | Commercial: ${p.commercial || '?'} | Club: ${p.gym_id} | Date: ${p.date}`
      ).join('\n')}`
    : '';

  return `Tu es AURALIX — IA tactique MegaFit (4 clubs: Doukkarate, Saiss, Casa Anfa, Casa Lady).
OPÉRATEUR IMPITOYABLE. Direct, zéro bavardage.

ÉTAT: ${sig.empire_status || 'INCONNU'}
CA MOIS: ${rev.month.toLocaleString()} DH | OBJ: ${rev.monthly_goal.toLocaleString()} DH (${sig.goal_progress_pct||0}%)
PRÉV: ${(sig.projected_month_end||0).toLocaleString()} DH | ÉCART: ${(sig.gap_to_goal||0).toLocaleString()} DH | REQ/J: ${(sig.required_daily||0).toLocaleString()} DH
VS M-1 (j1-${meta.day_of_month}): ${rev.vs_prev_month_pct > 0 ? '+' : ''}${rev.vs_prev_month_pct}%
DETTE: ${snap.debts.total_open.toLocaleString()} DH (${snap.debts.members_count} mbr) | DÉCAIS: ${dec.month_total.toLocaleString()} DH
MBR ACTIFS: ${snap.members.active_total} | EXPIRENT 30j: ${snap.members.expiring_30d} | EXPIRÉS: ${snap.members.expired_not_renewed}
INCIDENTS: ${snap.incidents.open_total} (${snap.incidents.critical} crit) | RESUB POSSIBLES: ${snap.members.resub?.possible_count || 0}

CALENDRIER: Ramadan 18fév-18mars | Eid Fitr 20mars | Eid Kbir 27mai | Juil-Août=creux | Sept=pic${subIntel}${topFormulas}${extRatio}${relanceBlock}${pendingBlock}

FORMAT OBLIGATOIRE:
- ULTRA-CONCIS: bullet points courts, jamais de paragraphes
- NE PAS RÉPÉTER les données brutes (noms, montants) que l'utilisateur voit déjà
- SYNTHÉTISER: "Top 5 débiteurs: 33K DH" au lieu de lister chaque nom
- CHIFFRES: toujours avec DH et % — jamais de texte générique
- ACTIONS: format → QUI + QUOI + QUAND (1 ligne par action)
- MAX 15 bullet points par réponse
- Pas de scripts d'appel ni de modèles génériques — juste les directives
- Classifier: ✅HEALTHY 👁WATCH ⚠️WARNING 🔴CRITICAL${sensorNote}${mem}`;
}


// ─── ROUTER ───────────────────────────────────────────────────────────────────
module.exports = function aiAgentRouter({ lc }) {
  const router = Router();
  const db = lc?.db;

  try { initAiTables(db); console.log('[AURALIX-AGENT] Tables initialized'); } catch(e) { console.error('[AURALIX-AGENT] Table init error:', e.message); }

  const getMeta = (key) => { try { return lc.getMeta?.(key); } catch { return null; } };
  const snap = (gym) => buildSnapshot(db, getMeta, gym);

  // ═══ 🧠 BACKGROUND INTELLIGENCE ENGINE ═══════════════════════════════════
  // Caches snapshot every 15 min + generates AI digest every 6 hours
  // So when user calls AI, data is INSTANT — no rebuilding from scratch
  const CACHE_INTERVAL  = 15 * 60 * 1000;  // 15 minutes
  const DIGEST_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours
  let lastDigestTime = 0;

  // In-memory cache for instant access
  let cachedSnapshot = null;
  let cachedSignals  = null;
  let cachedAlerts   = null;
  let cacheTimestamp = 0;

  function refreshCache(gymScope = 'all') {
    try {
      const s = snap(gymScope);
      const { signals, alerts } = runRules(s);
      cachedSnapshot = s;
      cachedSignals  = signals;
      cachedAlerts   = alerts;
      cacheTimestamp = Date.now();

      // Persist to DB so it survives restarts
      if (db) {
        try {
          db.prepare(`INSERT OR REPLACE INTO ai_snapshot_cache (id, gym_scope, snapshot_json, signals_json, alerts_json, updated_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`)
            .run(`cache_${gymScope}`, gymScope, JSON.stringify(s), JSON.stringify(signals), JSON.stringify(alerts));
        } catch (dbErr) { console.error('[AURALIX-BG] Cache DB write error:', dbErr.message); }
      }

      // Save alerts to DB
      saveAlerts(alerts, gymScope);

      console.log(`[AURALIX-BG] ✓ Cache refreshed (${gymScope}) — CA: ${s.revenue?.month?.toLocaleString() || 0} DH | ${alerts.length} alerts`);
      return { snapshot: s, signals, alerts };
    } catch (e) {
      console.error('[AURALIX-BG] Cache refresh error:', e.message);
      return null;
    }
  }

  // Get cached or fresh data — always fast
  function getCached(gymScope = 'all') {
    const cacheAge = Date.now() - cacheTimestamp;
    // If cache is fresh enough (< 20 min) and same scope, use it
    if (cachedSnapshot && cacheAge < CACHE_INTERVAL * 1.3 && (gymScope === 'all' || cachedSnapshot.meta?.gym_scope === gymScope)) {
      return { snapshot: cachedSnapshot, signals: cachedSignals, alerts: cachedAlerts, fromCache: true, cacheAge: Math.round(cacheAge / 1000) };
    }
    // Otherwise rebuild (and cache it)
    const result = refreshCache(gymScope);
    if (result) return { ...result, fromCache: false, cacheAge: 0 };
    // Last resort: try loading from DB
    if (db) {
      try {
        const row = db.prepare(`SELECT * FROM ai_snapshot_cache WHERE id=?`).get(`cache_${gymScope}`);
        if (row) {
          return {
            snapshot: JSON.parse(row.snapshot_json),
            signals: JSON.parse(row.signals_json),
            alerts: JSON.parse(row.alerts_json),
            fromCache: true, cacheAge: 999,
          };
        }
      } catch {}
    }
    return { snapshot: snap(gymScope), signals: {}, alerts: [], fromCache: false };
  }

  // Build daily digest context — accumulated AI memory
  function getDailyDigests(limit = 7) {
    if (!db) return [];
    try {
      return db.prepare(`SELECT date, digest_text, key_metrics, trends FROM ai_daily_digest ORDER BY date DESC LIMIT ?`).all(limit);
    } catch { return []; }
  }

  // Generate AI daily digest (runs every 6h)
  async function generateDigest() {
    try {
      const { snapshot: s, signals } = getCached('all');
      if (!s?.revenue) return;

      const today = new Date(Date.now() + 3600000).toISOString().slice(0, 10);
      const digestId = `digest_${today}_${Date.now()}`;

      // Check if we already have a digest for today
      if (db) {
        const existing = db.prepare(`SELECT COUNT(*) cnt FROM ai_daily_digest WHERE date=?`).get(today);
        if ((existing?.cnt || 0) >= 4) {
          console.log('[AURALIX-BG] Already have enough digests for today, skipping');
          return;
        }
      }

      // Build compact metrics snapshot for digest
      const metrics = {
        date: today,
        ca_month: s.revenue.month,
        ca_today: s.revenue.today,
        vs_prev: s.revenue.vs_prev_month_pct,
        goal_pct: signals.goal_progress_pct || 0,
        debt: s.debts?.total_open || 0,
        debt_members: s.debts?.members_count || 0,
        active_members: s.members?.active_total || 0,
        expiring: s.members?.expiring_30d || 0,
        incidents_open: s.incidents?.open_total || 0,
        decaissements: s.decaissements?.month_total || 0,
        empire_status: signals.empire_status || 'UNKNOWN',
        top_gyms: s.gyms?.map(g => ({ name: g.name, rev: g.revenue, growth: g.growth_pct })) || [],
      };

      // Previous digests for trend context
      const prevDigests = getDailyDigests(3);
      const trendContext = prevDigests.length > 0
        ? `\nHISTORIQUE RÉCENT:\n${prevDigests.map(d => `${d.date}: ${d.digest_text?.slice(0, 150) || '?'}`).join('\n')}`
        : '';

      // Ask AI to generate a concise digest
      const digestPrompt = `Données du jour ${today}:\n${JSON.stringify(metrics)}${trendContext}\n\nGénère un digest en 3-4 lignes max: 1) Statut + CA 2) Tendances vs jours précédents 3) Action prioritaire. Sois ultra-concis, style tableau de bord.`;

      const messages = compactMessages([
        { role: 'system', content: 'Tu es AURALIX, agent BI MegaFit. Génère des digests concis en français.' },
        { role: 'user', content: digestPrompt }
      ]);

      const digestText = await groq(messages, false);

      // Save digest to DB
      if (db && digestText) {
        try {
          db.prepare(`INSERT OR IGNORE INTO ai_daily_digest (id, date, gym_scope, digest_text, key_metrics, trends) VALUES (?, ?, 'all', ?, ?, ?)`)
            .run(digestId, today, digestText.slice(0, 1000), JSON.stringify(metrics), JSON.stringify(prevDigests.map(d => d.key_metrics).slice(0, 3)));
          console.log(`[AURALIX-BG] ✓ Daily digest generated for ${today}`);
        } catch (dbErr) { console.error('[AURALIX-BG] Digest DB error:', dbErr.message); }
      }
    } catch (e) {
      console.error('[AURALIX-BG] Digest generation error:', e.message);
    }
  }

  // ── Start background engine ────────────────────────────────────────────────
  // Initial cache on startup (delayed 10s to let DB settle)
  setTimeout(() => {
    console.log('[AURALIX-BG] 🚀 Starting background intelligence engine...');
    refreshCache('all');
  }, 10000);

  // Periodic cache refresh every 15 min
  setInterval(() => {
    refreshCache('all');
    // Generate digest every 6 hours
    if (Date.now() - lastDigestTime > DIGEST_INTERVAL) {
      lastDigestTime = Date.now();
      generateDigest().catch(e => console.error('[AURALIX-BG] Digest error:', e.message));
    }
  }, CACHE_INTERVAL);

  console.log('[AURALIX-BG] ⏰ Cache: every 15min | Digest: every 6h');

  // ── Save alert to DB ───────────────────────────────────────────────────────
  function saveAlerts(alerts, gym = 'all') {
    if (!db || !alerts?.length) return;
    const ins = db.prepare(`INSERT OR IGNORE INTO ai_alerts (id, alert_type, priority, title, message, gym, status) VALUES (?,?,?,?,?,?,'OPEN')`);
    const ym = new Date().toISOString().slice(0, 7);
    alerts.forEach(a => {
      try { ins.run(`alert_${a.type}_${gym}_${ym}`, a.type, a.priority, a.title, a.message || '', a.gym || gym); } catch {}
    });
  }

  // ── GET /api/ai/snapshot ───────────────────────────────────────────────────
  router.get('/api/ai/snapshot', verifyAzureToken, (req, res) => {
    try {
      const { snapshot: s, signals, alerts, fromCache, cacheAge } = getCached(req.query.gym || 'all');
      res.json({ snapshot: s, signals, alerts, fromCache, cacheAgeSec: cacheAge });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── GET /api/ai/cache-status ───────────────────────────────────────────────
  router.get('/api/ai/cache-status', verifyAzureToken, (req, res) => {
    try {
      const digests = getDailyDigests(5);
      res.json({
        cached: !!cachedSnapshot,
        cacheAgeSec: cachedSnapshot ? Math.round((Date.now() - cacheTimestamp) / 1000) : null,
        lastRefresh: cachedSnapshot ? new Date(cacheTimestamp).toISOString() : null,
        empireStatus: cachedSignals?.empire_status || 'UNKNOWN',
        alertCount: cachedAlerts?.length || 0,
        recentDigests: digests.map(d => ({ date: d.date, summary: d.digest_text?.slice(0, 200) })),
        engine: { cacheInterval: '15min', digestInterval: '6h' },
      });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/ask ───────────────────────────────────────────────────────
  // OpenAI function-calling: the model queries the REAL data via tools (member,
  // club revenue, décaissements, debtors, activity log) — no more 3500-char keyhole.
  // Falls back to the legacy Groq path if OpenAI is unavailable, so nothing breaks.
  router.post('/api/ai/ask', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { question, gym = 'all' } = req.body;
      const persona = req.body.persona === 'david' ? 'david' : 'auralix';
      if (!question?.trim()) return res.status(400).json({ error: 'Question required' });

      const { snapshot: s, signals, alerts, fromCache } = getCached(gym);
      saveAlerts(alerts, gym);

      const digests = getDailyDigests(3);
      const digestMemory = digests.length > 0
        ? `\n\nMÉMOIRE (digests récents): ${digests.map(d => `[${d.date}] ${(d.digest_text || '').slice(0, 120)}`).join(' · ')}`
        : '';

      // ── Primary: OpenAI director brain with retrieval tools (Auralix or David persona) ──
      if (hasOpenAI()) {
        try {
          const sysPrompt = (persona === 'david' ? buildDavidSystemPrompt(s, signals) : buildAskSystemPrompt(s, signals)) + digestMemory;
          const { reply, toolsUsed, privacy } = await openaiAgentAnswer(db, sysPrompt, question);
          return res.json({ reply, signals, alerts, empire_status: signals.empire_status, fromCache, engine: 'openai', toolsUsed, privacy, persona });
        } catch (oe) {
          console.error('[AI/ask] OpenAI failed → Groq fallback:', oe.message);
        }
      }

      // ── Fallback: legacy Groq path (truncated snapshot) — same privacy guarantee ──
      const priv = aiTools.makePrivacy(strictPrivacy());
      const debtsCtx = priv.enabled
        ? { ...s.debts, top_debtors: (s.debts.top_debtors || []).map(d => ({ ...d, name: priv.name(d.name) })) }
        : s.debts;
      const ctxJson = JSON.stringify({
        revenue: s.revenue, members: { active_total: s.members.active_total, expiring_30d: s.members.expiring_30d, expired_not_renewed: s.members.expired_not_renewed, resub: s.members.resub },
        door_traffic: s.door_traffic, debts: debtsCtx, decaissements: { month_total: s.decaissements.month_total, by_gym: s.decaissements.by_gym, by_category: s.decaissements.by_category },
        incidents: { open_total: s.incidents.open_total, critical: s.incidents.critical }, gyms: s.gyms, commercials: s.commercials.slice(0, 8),
        historical_revenue: s.historical_revenue.slice(-6), subscription_intel: s.subscription_intel?.slice(0, 15),
      });
      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) + digestMemory + `\n\n=== DONNÉES ===\n${ctxJson.slice(0, 3500)}` },
        { role: 'user', content: question }
      ];
      const reply = priv.restore(await groq(messages, true));
      res.json({ reply, signals, alerts, empire_status: signals.empire_status, fromCache, engine: 'groq', privacy: priv.enabled });
    } catch(e) { console.error('[AI/ask]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/david-live ───────────────────────────────────────────────
  // David runs a live working session WITH Auralix to co-build a x10 plan.
  // Turn-based: the client posts the transcript so far, we compute the NEXT
  // single turn and return it (so each line can appear live in the UI). David
  // drives + reasons; Auralix answers with REAL data via tools. Ends on the plan.
  router.post('/api/ai/david-live', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gym = 'all' } = req.body;
      const rounds = Math.max(1, Math.min(4, Number(req.body.rounds) || 2)); // Auralix answers per session (each round = 2 model calls)
      const transcript = Array.isArray(req.body.transcript) ? req.body.transcript : [];
      if (!hasOpenAI()) return res.status(200).json({ error: 'OPENAI_API_KEY manquante sur le serveur', done: true });

      const { snapshot: s, signals } = getCached(gym);
      const last = transcript[transcript.length - 1];
      const auralixTurns = transcript.filter(t => t.speaker === 'auralix').length;

      // Whose turn is it? (state derived entirely from the transcript)
      if (transcript.length === 0) {
        const text = await davidSays(s, signals, transcript, 'open');
        return res.json({ turn: { speaker: 'david', text }, done: false, rounds });
      }
      if (last.speaker === 'david') {
        // Auralix answers David with real data (aggregates — keeps member PII out).
        const auralixSys = buildAskSystemPrompt(s, signals);
        const q = `[SÉANCE INTERNE. David — ton closer — te met la pression pour bâtir un plan x10. Réponds-lui en AGRÉGATS: montants, compteurs, clubs, commerciaux, formules. N'énumère PAS des noms de membres individuels — reste au niveau chiffres/segments. Sois précis et court.]\n\nDavid: ${last.text}`;
        const { reply, privacy } = await openaiAgentAnswer(db, auralixSys, q);
        return res.json({ turn: { speaker: 'auralix', text: reply }, done: false, rounds, privacy });
      }
      // last.speaker === 'auralix' → David reacts, or delivers the final plan
      const finalTurn = auralixTurns >= rounds;
      const text = await davidSays(s, signals, transcript, finalTurn ? 'plan' : 'react');
      return res.json({ turn: { speaker: 'david', text, plan: finalTurn }, done: finalTurn, rounds });
    } catch (e) {
      console.error('[AI/david-live]', e.message);
      res.status(500).json({ error: e.message, done: true });
    }
  });

  // ── POST /api/ai/director-brief ───────────────────────────────────────────
  // The Morning Brief: full-snapshot (untruncated) executive briefing via OpenAI.
  // State → What changed → Why → Top 3 actions → Risks. Stored for instant reload.
  router.post('/api/ai/director-brief', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gym = 'all' } = req.body;
      const { snapshot: s, signals } = getCached(gym);
      if (!hasOpenAI()) return res.status(200).json({ brief: null, engine: 'none', error: 'OPENAI_API_KEY manquante sur le serveur' });

      const sys = `Tu es AURALIX, le DIRECTEUR IA de MegaFit (4 clubs: Fès Doukkarate, Fès Saïss, Casa Anfa, Casa Lady). Rédige le BRIEFING MATINAL du directeur à partir des données COMPLÈTES fournies. Style exécutif, dense, chiffré, zéro bla-bla.

STRUCTURE OBLIGATOIRE (français, avec ces titres):
1. 📊 ÉTAT — statut global (✅/👁/⚠️/🔴) + CA mois vs objectif + projection fin de mois.
2. 🔀 CE QUI A CHANGÉ — variations clés vs mois dernier (CA par club, décaissements, dette, membres).
3. 🧭 POURQUOI — la cause la plus probable des variations importantes.
4. 🎯 TOP 3 ACTIONS AUJOURD'HUI — chacune: QUI + QUOI + IMPACT chiffré attendu (DH/%).
5. 🚨 RISQUES — 1 à 3 alertes (dette critique, churn, décaissements anormaux, activité staff suspecte).

Chaque point avec des CHIFFRES RÉELS tirés des données (DH, %). Note: Casa Anfa et Casa Lady n'ont PAS de capteur de porte — ne jamais alerter sur leur trafic. Tu es un CONSEILLER: tu recommandes, tu ne modifies rien.`;
      // Pseudonymize debtor names before the brief context leaves for OpenAI; restore after.
      const priv = aiTools.makePrivacy(strictPrivacy());
      const ctx = briefContext(s);
      if (priv.enabled && ctx.debts?.top_debtors) ctx.debts.top_debtors = ctx.debts.top_debtors.map(d => ({ ...d, name: priv.name(d.name) }));
      const messages = [
        { role: 'system', content: sys },
        { role: 'user', content: `Données complètes (${s.meta.gym_scope}, période ${s.meta.period}, jour ${s.meta.day_of_month}/${s.meta.days_in_month}):\n${JSON.stringify(ctx)}` },
      ];
      // The brief is long-form over a big snapshot: keep effort LOW (otherwise hidden
      // reasoning tokens swallow the whole budget and the brief comes back empty) and
      // give it enough room to actually write the 5 sections.
      const data = await openaiCall(messages, { maxTokens: 2600, temperature: 0.35, effort: 'low' });
      const brief = priv.restore(data.choices?.[0]?.message?.content || '');

      try {
        const today = new Date(Date.now() + 3600000).toISOString().slice(0, 10);
        db.prepare(`INSERT OR REPLACE INTO ai_director_brief (id, date, gym_scope, brief_text, created_at) VALUES (?,?,?,?,datetime('now'))`)
          .run(`brief_${gym}_${today}`, today, gym, brief);
      } catch (dbErr) { console.error('[AI/director-brief] persist:', dbErr.message); }

      res.json({ brief, engine: 'openai', period: s.meta.period, generated_at: new Date().toISOString() });
    } catch(e) { console.error('[AI/director-brief]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── GET /api/ai/churn-risk ── ranked members at risk of not renewing ──
  // Direct dashboard endpoint → REAL names (privacy mode only guards data sent
  // to OpenAI; this goes straight to the admin's own screen so they can act).
  router.get('/api/ai/churn-risk', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      res.json(aiTools.churnRisk(db, { gym: req.query.gym || 'all', limit: req.query.limit || 25 }));
    } catch(e) { console.error('[AI/churn-risk]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── GET /api/ai/director-brief ── instant reload of today's stored brief ──
  router.get('/api/ai/director-brief', verifyAzureToken, (req, res) => {
    try {
      const gym = req.query.gym || 'all';
      const today = new Date(Date.now() + 3600000).toISOString().slice(0, 10);
      const row = db.prepare(`SELECT brief_text, date, created_at FROM ai_director_brief WHERE id=?`).get(`brief_${gym}_${today}`)
               || db.prepare(`SELECT brief_text, date, created_at FROM ai_director_brief WHERE gym_scope=? ORDER BY created_at DESC LIMIT 1`).get(gym);
      res.json({ brief: row?.brief_text || null, date: row?.date || null, cached: !!row });
    } catch(e) { res.json({ brief: null, error: e.message }); }
  });

  // ── POST /api/ai/scan ──────────────────────────────────────────────────────
  router.post('/api/ai/scan', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gym = 'all' } = req.body;
      const { snapshot: s, signals, alerts, fromCache } = getCached(gym);
      saveAlerts(alerts, gym);

      const SCHEMA = `Réponds UNIQUEMENT en JSON valide (aucun texte avant/après):\n{"empire_status":"HEALTHY|WATCH|WARNING|CRITICAL","mood":"healthy|watch|warning|critical","executive_summary":"string","critical_alerts":[{"level":"critical","title":"string","detail":"string","gym":"string"}],"watch_points":[{"title":"string","detail":"string"}],"growth_opportunities":[{"title":"string","detail":"string","impact":"string"}],"priority_actions":[{"title":"string","owner":"string","deadline":"string","impact":"HIGH|MEDIUM","gym":"string","description":"string"}]}`;
      // Accurate, un-truncated context — includes the PRE-COMPUTED variation so the model never recomputes a %.
      const ctxScan = {
        revenue: s.revenue, // revenue.vs_prev_month_pct is the correct pro-rata variation
        members: { active_total: s.members.active_total, expiring_30d: s.members.expiring_30d, expired_not_renewed: s.members.expired_not_renewed, resub: s.members.resub },
        debts: { total_open: s.debts.total_open, members_count: s.debts.members_count },
        decaissements: { month_total: s.decaissements.month_total, expense_to_revenue_pct: s.decaissements.expense_to_revenue_pct, by_category: s.decaissements.by_category },
        incidents: { open_total: s.incidents.open_total, critical: s.incidents.critical }, commercials: s.commercials.slice(0, 8), gyms: s.gyms, subscription_intel: s.subscription_intel?.slice(0, 10),
      };
      const sysScan = `Tu es AURALIX, IA tactique MegaFit (${s.meta.gym_scope}, ${s.meta.period}, jour ${s.meta.day_of_month}/${s.meta.days_in_month}). Analyse tactique de l'empire.
RÈGLE ABSOLUE (CHIFFRES): utilise EXACTEMENT les valeurs fournies. \`revenue.vs_prev_month_pct\` EST la variation correcte vs le mois dernier au même jour (pro-rata) — ne recalcule JAMAIS un pourcentage toi-même, et ne compare pas le mois en cours (partiel) au mois dernier complet. Casa Anfa et Casa Lady n'ont pas de capteur de porte — ne jamais alerter sur leur trafic.
${SCHEMA}`;
      const messages = [
        { role: 'system', content: sysScan },
        { role: 'user', content: `Données:\n${JSON.stringify(ctxScan)}` },
      ];

      // Primary: OpenAI (gpt-5.5 — accurate, doesn't miscompute). Fallback: Groq.
      let raw = '';
      if (hasOpenAI()) {
        try { const d = await openaiCall(messages, { maxTokens: 1700 }); raw = d.choices?.[0]?.message?.content || ''; }
        catch (oe) { console.error('[AI/scan] OpenAI failed → Groq:', oe.message); }
      }
      if (!raw) raw = await groq([{ role: 'system', content: buildSysPrompt(s, signals) + '\n\n' + sysScan }, messages[1]], true);
      let parsed;
      try {
        const m = raw.match(/\{[\s\S]*\}/);
        parsed = m ? JSON.parse(m[0]) : null;
      } catch { parsed = null; }

      if (!parsed) {
        parsed = { empire_status: signals.empire_status, mood: signals.empire_status.toLowerCase(), executive_summary: raw.slice(0, 400), critical_alerts: alerts.filter(a=>a.priority==='CRITICAL').map(a=>({level:'critical',title:a.title,detail:a.message,gym:a.gym})), watch_points: [], growth_opportunities: [], priority_actions: [] };
      }

      // Auto-create action cards
      if (db && parsed.priority_actions?.length) {
        const ins = db.prepare(`INSERT OR IGNORE INTO ai_actions (id,title,description,gym,assigned_to,priority,status,deadline,source) VALUES (?,?,?,?,?,?,'OPEN',?,'scan')`);
        parsed.priority_actions.forEach(a => {
          const id = `scan_action_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
          try { ins.run(id, a.title, a.description||'', a.gym||gym, a.owner||'Manager', a.impact||'MEDIUM', a.deadline||''); } catch {}
        });
      }

      res.json({ ...parsed, signals, rules_alerts: alerts });
    } catch(e) { console.error('[AI/scan]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/startup-brief ─────────────────────────────────────────────
  router.post('/api/ai/startup-brief', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { snapshot: s, signals, alerts } = getCached(req.body?.gym || 'all');
      const critCount = alerts.filter(a=>a.priority==='CRITICAL').length;

      // Inject digest memory for context
      const digests = getDailyDigests(3);
      const digestCtx = digests.length > 0
        ? `\n\nMÉMOIRE IA:\n${digests.map(d => `[${d.date}] ${d.digest_text?.slice(0, 120)}`).join('\n')}`
        : '';

      const messages = compactMessages([
        { role: 'system', content: buildSysPrompt(s, signals) + digestCtx },
        { role: 'user', content: `Génère le brief CEO matinal en 5 sections numérotées:\n1. STATUT EMPIRE (${signals.empire_status})\n2. CHIFFRES CLÉS (CA, objectif, prévision)\n3. ALERTES CRITIQUES (${critCount} détectée(s))\n4. OPPORTUNITÉ DU JOUR\n5. DIRECTIVE PRIORITAIRE\n\nSois direct et actionnable. Termine par une seule instruction pour l'équipe aujourd'hui.` }
      ]);
      const brief = await groq(messages, false);
      saveAlerts(alerts, 'all');
      res.json({ brief, signals, alerts, empire_status: signals.empire_status });
    } catch(e) { console.error('[AI/startup-brief]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── POST /api/ai/quick/:mode ───────────────────────────────────────────────
  const QUICK_PROMPTS = {
    'find-money':       'Sources argent non collecté. Format STRICT:\n• DETTES: total + top 3 clubs — pas de liste de noms\n• RESUB: combien de membres récupérables + montant estimé\n• PIPELINE: inscriptions en attente (montant total)\n• PLAN 7J: 1 ligne par jour → action + responsable + objectif DH\nMax 12 bullet points.',
    'recover-debt':     'Analyse créances. Format STRICT:\n• RÉSUMÉ: total DH, nb débiteurs, top 3 clubs\n• PRIORITÉ HAUTE: nb personnes > 5000 DH (montant total)\n• PRIORITÉ MOYENNE: nb personnes 2000-5000 DH\n• PRIORITÉ BASSE: nb personnes < 2000 DH\n• PLAN ACTION: 3 actions max → QUI + QUOI + QUAND\nNe PAS lister chaque débiteur individuellement. Max 10 bullets.',
    'coach-commercial': 'Classement commerciaux. Format STRICT: 1 ligne par commercial:\n• NOM (club): CA DH | X inscrip | ticket moy | appels X% → verdict CHASSEUR/DORT/OK\nPuis 3 directives coaching max. Ne pas répéter les données brutes.',
    'renewals':         'Campagne renouvellement. Format STRICT:\n• CIBLE: X membres expirent 30j + Y resub possibles = Z prospects\n• TOP CLUBS à cibler (1 ligne par club)\n• STRATÉGIE: 3 actions max → timing + formule à pousser + responsable\nPas de scripts d\'appel. Max 8 bullets.',
    'forecast':         'Prévision fin mois. Format STRICT:\n• PROJECTION: X DH fin mois vs objectif Y DH = écart Z DH\n• REQUIS/JOUR: X DH (vs moyenne actuelle Y DH/j)\n• PAR COMMERCIAL: répartition objectif restant\n• RISQUES: 2-3 facteurs max\nMax 8 bullets.',
    'incidents':        'Incidents ouverts. Format STRICT: 1 ligne par incident:\n• [CRIT/WARN] Club: titre → impact business + action\nMax 8 bullets.',
    'courses':          'Analyse cours. Format STRICT:\n• REMPLISSAGE MOY: X% | COMPLETS: Y | SOUS-REMPLIS: Z\n• TOP 3 cours populaires (1 ligne chacun)\n• 3 optimisations max\nMax 8 bullets.',
    'birthdays':        'Anniversaires. Format STRICT:\n• CE MOIS: X anniversaires → opportunité engagement\n• STRATÉGIE: 3 actions max → offre + timing + responsable\nMax 6 bullets.',
    'subscriptions':    'Formules abonnement. Format STRICT: 1 ligne par formule:\n• FORMULE (club): X vendus | CA Y DH | trend ↑↓→\nPuis 3 recommandations max. Max 12 bullets.',
    'commercial-activity': 'Activité commerciaux. Format STRICT: 1 ligne par personne:\n• NOM: appels X/Y (Z%) | intéressés: A | renouvelés: B → verdict\nPuis 2 directives. Max 10 bullets.',
    'pipeline':         'Pipeline inscriptions. Format STRICT:\n• TOTAL: X inscriptions en attente = Y DH dormant\n• PAR CLUB: 1 ligne par club → nb + montant\n• ACTIONS: 3 max → QUI débloquer QUOI avant QUAND\nMax 8 bullets.',
  };

  router.post('/api/ai/quick/:mode', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { mode } = req.params;
      const prompt = QUICK_PROMPTS[mode];
      if (!prompt) return res.status(400).json({ error: `Unknown mode: ${mode}` });
      const { snapshot: s, signals } = getCached(req.body?.gym || 'all');
      const ctxJson = JSON.stringify({ revenue: s.revenue, debts: s.debts, members: s.members, commercials: s.commercials.slice(0,6), gyms: s.gyms, courses: s.courses, decaissements: { month_total: s.decaissements.month_total, by_gym: s.decaissements.by_gym }, incidents: { open_total: s.incidents.open_total, critical: s.incidents.critical }, subscription_intel: s.subscription_intel?.slice(0,10), top_formulas_empire: s.top_formulas_empire?.slice(0,5), extension_ratio: s.extension_ratio, relance_performance: s.relance_performance?.slice(0,6), pending_inscriptions_detailed: s.pending_inscriptions_detailed?.slice(0,5) }, null, 0).slice(0, 3500);
      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) + `\n\n=== DONNÉES ===\n${ctxJson}` },
        { role: 'user', content: prompt }
      ];
      const reply = await groq(messages, true);
      res.json({ reply, mode, signals, empire_status: signals.empire_status });
    } catch(e) { console.error('[AI/quick]', e.message); res.status(500).json({ error: e.message }); }
  });

  // ── Health check (rules only, no LLM) ─────────────────────────────────────
  router.get('/api/ai/health-check', verifyAzureToken, (req, res) => {
    try {
      const { snapshot: s, signals, alerts, fromCache, cacheAge } = getCached(req.query.gym || 'all');
      const openActCount = db ? db.prepare(`SELECT COUNT(*) cnt FROM ai_actions WHERE status='OPEN'`).get()?.cnt || 0 : 0;
      const openAlertCount = db ? db.prepare(`SELECT COUNT(*) cnt FROM ai_alerts WHERE status='OPEN'`).get()?.cnt || 0 : 0;
      res.json({ empire_status: signals.empire_status, signals, alerts, open_actions: openActCount, open_alerts: openAlertCount, fromCache, cacheAgeSec: cacheAge });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Actions CRUD ───────────────────────────────────────────────────────────
  router.get('/api/ai/actions', verifyAzureToken, (req, res) => {
    try {
      if (!db) return res.json([]);
      const status = req.query.status;
      const rows = status ? db.prepare(`SELECT * FROM ai_actions WHERE status=? ORDER BY created_at DESC LIMIT 50`).all(status) : db.prepare(`SELECT * FROM ai_actions ORDER BY created_at DESC LIMIT 50`).all();
      res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.post('/api/ai/action', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      const { title, description, gym='all', assigned_to='Manager', priority='MEDIUM', expected_impact, deadline } = req.body;
      if (!title) return res.status(400).json({ error: 'title required' });
      const id = `action_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
      db.prepare(`INSERT INTO ai_actions (id,title,description,gym,assigned_to,priority,expected_impact,deadline,source) VALUES (?,?,?,?,?,?,?,?,'manual')`).run(id, title, description||'', gym, assigned_to, priority, expected_impact||'', deadline||'');
      res.json({ id, title, status:'OPEN' });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.patch('/api/ai/actions/:id', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      const { status } = req.body;
      if (!['OPEN','IN_PROGRESS','DONE','IGNORED','ESCALATED'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
      const done = status === 'DONE' ? new Date().toISOString() : null;
      db.prepare(`UPDATE ai_actions SET status=?, completed_at=? WHERE id=?`).run(status, done, req.params.id);
      res.json({ id: req.params.id, status });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Memory CRUD ────────────────────────────────────────────────────────────
  router.get('/api/ai/memory', verifyAzureToken, (req, res) => {
    try {
      if (!db) return res.json([]);
      res.json(db.prepare(`SELECT * FROM ai_memory WHERE (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY importance DESC, created_at DESC LIMIT 30`).all());
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.post('/api/ai/memory', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      const { note, type='STRATEGY', scope='ALL_EMPIRE', gym='all', importance='HIGH', expires_days } = req.body;
      if (!note?.trim()) return res.status(400).json({ error: 'note required' });
      const id = `mem_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
      const expires = expires_days ? new Date(Date.now() + expires_days * 86400000).toISOString() : null;
      db.prepare(`INSERT INTO ai_memory (id,type,scope,gym,note,importance,expires_at) VALUES (?,?,?,?,?,?,?)`).run(id, type, scope, gym, note.trim(), importance, expires);
      res.json({ id, note, type, importance });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.delete('/api/ai/memory/:id', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      db.prepare(`DELETE FROM ai_memory WHERE id=?`).run(req.params.id);
      res.json({ deleted: req.params.id });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Alerts ─────────────────────────────────────────────────────────────────
  router.get('/api/ai/alerts', verifyAzureToken, (req, res) => {
    try {
      if (!db) return res.json([]);
      res.json(db.prepare(`SELECT * FROM ai_alerts WHERE status='OPEN' ORDER BY created_at DESC LIMIT 30`).all());
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  router.patch('/api/ai/alerts/:id/resolve', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      if (!db) return res.status(503).json({ error: 'DB unavailable' });
      db.prepare(`UPDATE ai_alerts SET status='RESOLVED', resolved_at=datetime('now') WHERE id=?`).run(req.params.id);
      res.json({ id: req.params.id, status: 'RESOLVED' });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ═══ 🔥 POST /api/ai/devil-scan — Deep Business Intelligence Scan ═══════════════
  router.post('/api/ai/devil-scan', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gym = 'all' } = req.body;
      const { snapshot: s, signals, alerts } = getCached(gym);
      saveAlerts(alerts, gym);

      // Build the most complete data payload possible
      const fullCtx = JSON.stringify({
        revenue: s.revenue, members: s.members, debts: s.debts,
        decaissements: s.decaissements, incidents: s.incidents,
        commercials: s.commercials, gyms: s.gyms, courses: s.courses,
        subscription_intel: s.subscription_intel,
        top_formulas_empire: s.top_formulas_empire,
        extension_ratio: s.extension_ratio,
        relance_performance: s.relance_performance,
        pending_inscriptions_detailed: s.pending_inscriptions_detailed,
        door_traffic: s.door_traffic,
      }, null, 0);

      const devilPrompt = `Tu es en MODE ANALYSE PROFONDE. Scanne l'intégralité de l'empire ${s.meta.gym_scope}.

Génère un rapport JSON COMPLET avec cette structure EXACTE (aucun texte avant ou après le JSON):
{
  "empire_status": "HEALTHY|WATCH|WARNING|CRITICAL",
  "executive_summary": "Résumé exécutif en 2-3 phrases percutantes",
  "revenue_leaks": [
    {"source": "nom de la fuite", "amount_dh": number, "action": "solution concrète", "owner": "nom du responsable", "deadline": "délai"}
  ],
  "subscription_analysis": {
    "best_formulas": [{"formula": "nom", "gym": "club", "sold": number, "revenue_dh": number, "trend": "RISING|STABLE|FALLING"}],
    "underperforming": [{"formula": "nom", "gym": "club", "issue": "problème détecté", "recommendation": "action"}],
    "cross_sell_opportunities": ["formule X de club A devrait être poussée dans club B"]
  },
  "commercial_ranking": [
    {"name": "nom", "gym": "club", "score": number, "revenue_dh": number, "inscriptions": number, "call_rate_pct": number, "verdict": "CHASSEUR|PERFORMANT|EN_DANGER|DORT", "coaching": "directive"}
  ],
  "growth_signals": [{"signal": "observation", "opportunity": "action", "impact": "HIGH|MEDIUM"}],
  "critical_alerts": [{"level": "critical|warning", "title": "titre", "detail": "détail", "gym": "club"}],
  "seven_day_plan": [
    {"day": "Jour 1", "action": "quoi faire", "owner": "qui", "expected_revenue": number}
  ]
}`;

      const messages = [
        { role: 'system', content: buildSysPrompt(s, signals) + `\n\n=== DONNÉES COMPLÈTES ===\n${fullCtx.slice(0, 6000)}` },
        { role: 'user', content: devilPrompt }
      ];

      const raw = await groq(messages, true);
      let parsed;
      try {
        const m = raw.match(/\{[\s\S]*\}/);
        parsed = m ? JSON.parse(m[0]) : null;
      } catch { parsed = null; }

      if (!parsed) {
        parsed = {
          empire_status: signals.empire_status,
          executive_summary: raw.slice(0, 500),
          revenue_leaks: [], subscription_analysis: { best_formulas: [], underperforming: [], cross_sell_opportunities: [] },
          commercial_ranking: [], growth_signals: [],
          critical_alerts: alerts.filter(a => a.priority === 'CRITICAL').map(a => ({ level: 'critical', title: a.title, detail: a.message, gym: a.gym })),
          seven_day_plan: [],
        };
      }

      // Auto-create action cards from 7-day plan
      if (db && parsed.seven_day_plan?.length) {
        const ins = db.prepare(`INSERT OR IGNORE INTO ai_actions (id,title,description,gym,assigned_to,priority,status,deadline,source) VALUES (?,?,?,?,?,?,'OPEN',?,'devil-scan')`);
        parsed.seven_day_plan.forEach(a => {
          const id = `devil_${Date.now()}_${Math.random().toString(36).slice(2,5)}`;
          try { ins.run(id, a.action, `Plan 7 jours: ${a.day}`, gym, a.owner || 'Manager', 'HIGH', a.day || ''); } catch {}
        });
      }

      res.json({ ...parsed, signals, rules_alerts: alerts, data_sources_used: ['revenue', 'members', 'debts', 'decaissements', 'subscriptions', 'commercials', 'relance', 'entries', 'incidents', 'courses'] });
    } catch(e) { console.error('[AI/devil-scan]', e.message); res.status(500).json({ error: e.message }); }
  });

  return router;
};
