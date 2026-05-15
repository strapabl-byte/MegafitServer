'use strict';
// lib/resubEngine.js — Re-Subscription Intelligence Engine (singleton)
// Optimised: CSV parsed on first call, then cached in-memory for instant reuse.
// Uses bigram index for O(k) candidate pre-filter before Levenshtein on top-N.
// Exported as a shared module so sales.js and sales.resub.js use the same instance.

const fs   = require('fs');
const path = require('path');

const ODOO_CSV_PATH = path.join(__dirname, '../odoo/all_members_all_clubs.csv');

const CLUB_TO_GYM = {
  'FES DOUKKARATE': 'dokarat',
  'FES MARJANE':    'marjane',
  'CASA ANFA':      'casa1',
  'CASA ANFA LADY': 'casa2',
};
const GYM_TO_CLUB = Object.fromEntries(Object.entries(CLUB_TO_GYM).map(([k,v])=>[v,k]));

let _csvCache = null;
let _bdayCache = null;
const _cleanNameCache = new Map();

const MOROCCAN_FIRST_NAMES = new Set([
  'AHMED','MOHAMED','MOHAMMED','HAMZA','YOUSSEF','YOUNES','AMINE','MEHDI','KARIM','OMAR',
  'HASSAN','HASSEN','RACHID','RACHIDA','KHALID','FOUAD','NABIL','SAAD','SAID','ANASS',
  'ANAS','ADAM','IBRAHIM','ALI','ABDELILAH','ABDELLAH','ABDELKADER','ABDERRAHMANE',
  'ABDERRAHMAN','ABDELHAK','ABDELHAMID','ABDELLATIF','ABDELOUAHAB','ABDELOUAHED',
  'ABDELAZIZ','ABDELMAJID','ABDELMOUNAIM','ABDELMOULA','ABDELMOUMEN','ABDERAHMAN',
  'ABDESSALAM','ABDESSAMAD','ABDESSLAM','MOUAD','MUSTAPHA','MOSTAFA','MOUNIR','MONTASER',
  'NOUR','NOURDINE','NORDINE','HICHAM','HISHAM','ISMAIL','ISMAEL','ILYAS','ILYASS',
  'JAWAD','JALLAL','JALAL','JAMAL','JAMIL','OTMANE','OTHMANE','OUSSAMA','OUISSAM',
  'SOUFIANE','SOUFYAN','SOFIANE','SALAH','SALIM','SLIM','SIMO','SIMOHAMED','SIHAM',
  'TAOUFIK','TAREK','TARIQ','WALID','WASSIM','WISSAM','YAHYA','YASSINE','YASSIN',
  'ZAKARIA','ZAKARIAE','ZAKARYA','ZIAD','ZINEDDINE','REDA','RADOUANE','RAOUF','RAYAN',
  'RYAN','RIDA','LOUBNA','LHOUSSAINE','LAHCEN','LARBI','LHOUCINE',
  'EL','BEN','AIT','ABI','BNOU','BENT',
  'FATIMA','KHADIJA','ZINEB','SARA','SARAH','LAYLA','LEILA','HAJAR','SOUKAINA',
  'NADIA','IMANE','HANAE','SANAE','MERIEM','MERYEM','ASMAA','ASMA','AMINA',
  'SIHAM','HOUDA','HODA','WIDAD','CHAIMA','CHAIMAE','OUMAIMA','MARIAM','MARYAM',
  'NAJAT','NAJET','NABILA','NOURA','NORA','NISRINE','NIHAL','MALAK','MANAL','MANEL',
  'HIND','HANA','HANANE','GHITA','GHIZLANE','GHIZLAN','FADWA','FATINE','FATIHA',
  'DOUNIA','DOHA','CHADIA','CHAMA','BTISSAM','BOUCHRA','BADREDDINE','BADR','BASMA',
  'AHLAM','AICHA','AISHA','ABIR','SAMIRA','SABRINE','SABRINA','SALWA','SAFAA','SAFA',
  'RAJAE','RAJAAE','RABAB','RANIA','RANYA','RHIMOU','LATIFA','LAMYAE','LAMIAE',
  'LOUBNA','LUBNA','LINA','LENA','IKRAM','INSAF','INTISSAR','ILHAM',
  'YOUSSRA','YOUSRA','WISSAL','WAFAA','WAFA',
]);

function cleanName(raw) {
  if (!raw) return '';
  const cached = _cleanNameCache.get(raw);
  if (cached !== undefined) return cached;
  const cleaned = raw
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '')
    .replace(/[\uFE00-\uFE0F\u200D\uFEFF]/g, '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^A-Z0-9 ]/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
  if (_cleanNameCache.size > 20000) _cleanNameCache.clear();
  _cleanNameCache.set(raw, cleaned);
  return cleaned;
}

function splitMoroccanName(name) {
  if (name.includes(' ') || name.length < 6) return name;
  for (const fn of MOROCCAN_FIRST_NAMES) {
    if (fn.length >= 3 && name.startsWith(fn) && name.length > fn.length) {
      const rest = name.slice(fn.length);
      if (rest.length >= 3) return `${fn} ${rest}`;
    }
  }
  for (const fn of MOROCCAN_FIRST_NAMES) {
    if (fn.length >= 3 && name.endsWith(fn) && name.length > fn.length) {
      const rest = name.slice(0, name.length - fn.length);
      if (rest.length >= 3) return `${rest} ${fn}`;
    }
  }
  return name;
}

function bigrams(str) {
  const s = str.replace(/\s+/g, '');
  const out = new Set();
  for (let i = 0; i < s.length - 1; i++) out.add(s.slice(i, i + 2));
  return out;
}

function levenshtein(a, b, maxDist = 999) {
  if (Math.abs(a.length - b.length) > maxDist) return maxDist + 1;
  const la = a.length, lb = b.length;
  if (la === 0) return lb;
  if (lb === 0) return la;
  let prev = Array.from({ length: lb + 1 }, (_, i) => i);
  for (let i = 1; i <= la; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > maxDist) return maxDist + 1;
    prev = cur;
  }
  return prev[lb];
}

function similarity(a, b) {
  if (!a || !b) return 0;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 100;
  return Math.round((1 - levenshtein(a, b, maxLen) / maxLen) * 100);
}

function tokenAwareSimilarity(queryClean, memberClean) {
  const qTokens = queryClean.split(' ').filter(t => t.length >= 2);
  const mTokens = memberClean.split(' ').filter(t => t.length >= 2);
  if (qTokens.length < 2 || mTokens.length < 2) return similarity(queryClean, memberClean);
  const tokenScores = qTokens.map(qt => Math.max(...mTokens.map(mt => similarity(qt, mt))));
  tokenScores.sort((a, b) => b - a);
  const best = tokenScores[0] || 0;
  const second = tokenScores[1] || 0;
  if (best >= 70 && second < 50) return Math.min(55, best - 20);
  const combined = Math.round(best * 0.60 + second * 0.40);
  return Math.max(combined, similarity(queryClean, memberClean));
}

function loadOdooCSV() {
  if (_csvCache) return _csvCache;
  console.log('📂 [ReSubEngine] Loading Odoo CSV…');
  let raw;
  try { raw = fs.readFileSync(ODOO_CSV_PATH, 'utf-8'); }
  catch (e) { console.error('❌ [ReSubEngine] CSV not found:', e.message); _csvCache = { members: [], bigramIndex: new Map() }; return _csvCache; }
  const lines = raw.split('\n').slice(1);
  const members = [];
  const bigramIndex = new Map();
  for (const line of lines) {
    if (!line.trim()) continue;
    const cols = line.split(',');
    const full_name = cols[0]?.trim();
    const club      = cols[6]?.trim();
    const status    = cols[7]?.trim();
    const subs_stop = cols[9]?.trim();
    const last_pay  = cols[11]?.trim();
    const x_birthday= cols[12]?.trim();
    if (!full_name || !club) continue;
    const cleaned = cleanName(full_name);
    const idx = members.length;
    members.push({ cleaned, full_name, club, gymId: CLUB_TO_GYM[club] || null, status, subs_stop, last_pay, x_birthday });
    for (const bg of bigrams(cleaned)) {
      if (!bigramIndex.has(bg)) bigramIndex.set(bg, new Set());
      bigramIndex.get(bg).add(idx);
    }
  }
  _csvCache = { members, bigramIndex, loadedAt: Date.now() };
  console.log(`✅ [ReSubEngine] Indexed ${members.length} members with ${bigramIndex.size} bigrams`);
  return _csvCache;
}

function _searchVariant(cleaned, members, bigramIndex) {
  const qBigrams = bigrams(cleaned);
  const candidateScore = new Map();
  for (const bg of qBigrams) {
    const hits = bigramIndex.get(bg);
    if (hits) for (const idx of hits) candidateScore.set(idx, (candidateScore.get(idx) || 0) + 1);
  }
  const TOP_N = 40;
  const candidates = [...candidateScore.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_N)
    .map(([idx]) => idx);
  if (candidates.length === 0) return { bestScore: 0, bestMember: null, candidates: [] };
  let bestScore = 0, bestMember = null;
  for (const idx of candidates) {
    const sc = tokenAwareSimilarity(cleaned, members[idx].cleaned);
    if (sc > bestScore) { bestScore = sc; bestMember = members[idx]; }
  }
  return { bestScore, bestMember, candidates };
}

function findBestMatch(queryName) {
  const { members, bigramIndex } = loadOdooCSV();
  if (!members.length) return null;
  const cleaned = cleanName(queryName);
  const v1 = _searchVariant(cleaned, members, bigramIndex);
  const split = splitMoroccanName(cleaned);
  const v2 = split !== cleaned ? _searchVariant(split, members, bigramIndex) : { bestScore: 0, bestMember: null, candidates: [] };
  const best = v2.bestScore > v1.bestScore ? v2 : v1;
  const usedName = v2.bestScore > v1.bestScore ? split : cleaned;
  const seen = new Set();
  const topCandidates = [...v1.candidates, ...v2.candidates]
    .filter(idx => { if (seen.has(idx)) return false; seen.add(idx); return true; })
    .slice(0, 8)
    .map(idx => ({
      name: members[idx].cleaned, full_name: members[idx].full_name,
      club: members[idx].club, gymId: members[idx].gymId,
      status: members[idx].status, subs_stop: members[idx].subs_stop,
      x_birthday: members[idx].x_birthday,
      score: tokenAwareSimilarity(usedName, members[idx].cleaned)
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 4);
  return {
    match: best.bestMember?.full_name || null,
    score: best.bestScore,
    prevClub: best.bestMember?.club || null,
    prevGymId: best.bestMember?.gymId || null,
    status: best.bestMember?.status || null,
    lastSub: best.bestMember?.subs_stop || null,
    usedVariant: usedName,
    wasSplit: usedName !== cleaned,
    topCandidates,
  };
}

const resubGroqLimiter = {
  lastCall: 0, cooldownUntil: 0, minGapMs: 4000, cooldownMs: 60000,
  isCooling() { return Date.now() < this.cooldownUntil; },
  trigger429() { this.cooldownUntil = Date.now() + this.cooldownMs; console.warn('[ReSubAI] 429 — cooling 60s'); },
  async wait() {
    const gap = this.minGapMs - (Date.now() - this.lastCall);
    if (gap > 0) await new Promise(r => setTimeout(r, gap));
    this.lastCall = Date.now();
  },
};

async function groqBatchValidate(possibles) {
  if (!possibles.length) return new Map();
  if (resubGroqLimiter.isCooling()) { console.log('[ReSubAI] Groq in cooldown'); return new Map(); }
  const GROQ_KEY = process.env.GROQ_API_KEY || process.env.GROQ_API_KEY_FALLBACK;
  if (!GROQ_KEY) return new Map();
  const CHUNK_SIZE = 8;
  const resultMap = new Map();
  for (let i = 0; i < possibles.length; i += CHUNK_SIZE) {
    const chunk = possibles.slice(i, i + CHUNK_SIZE);
    const idxToId = chunk.map(p => p.id);
    if (resubGroqLimiter.isCooling()) break;
    await resubGroqLimiter.wait();
    const rows = chunk.map((p, ci) => {
      const cands = (p.topCandidates || []).slice(0, 2).map(c => `${c.name.slice(0, 20)}(${c.score}%)`).join(' ') || '-';
      return `${ci + 1}:${p.cleanedNom}→${cands}`;
    }).join('\n');
    const prompt = `You are a senior data-quality engineer specialized in Moroccan identity reconciliation.\nTask: Match SOURCE inscriptions to MASTER (ODOO) candidates.\n\nRules:\n-Normalize: Mohamed/Mohammed/Med, Ahmed/Ahmad, Yassine/Yassin, Zakaria/Zakarya, etc.\n-Particles: EL, AL, BEN, BENT, IBN, OULD, AIT, SIDI (ignore or match as prefixes).\n-Names: FIRST LAST = LAST FIRST. Reversed tokens match.\n-Strictness: If family name structure differs even slightly -> N (NEW).\n-Doubt: Confidence <88% with different club/tokens -> P (POSSIBLE) or N.\n-Score <75% -> N.\n\nRows (NUM:NEW→ODOO_MATCHES):\n${rows}\n\nReply ONLY: [{"n":<NUM>,"v":"R(RESUB), N(NEW) or P(POSSIBLE)","c":<0-100>,"r":"<5 words raison audit>"}]`;
    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'llama-3.1-8b-instant', messages: [{ role: 'user', content: prompt }], temperature: 0.05, max_tokens: Math.min(chunk.length * 40 + 60, 400) }),
      });
      if (r.status === 413) continue;
      if (r.status === 429) { resubGroqLimiter.trigger429(); break; }
      if (!r.ok) continue;
      const data = await r.json();
      const text = data.choices?.[0]?.message?.content?.trim() || '';
      let verdicts = [];
      const arrMatch = text.match(/\[[\s\S]*?\]/);
      if (arrMatch) { try { verdicts = JSON.parse(arrMatch[0]); } catch (_) {} }
      for (const v of verdicts) {
        const rowIdx = (v?.n ?? v?.num ?? 0) - 1;
        if (rowIdx >= 0 && rowIdx < chunk.length) {
          resultMap.set(String(idxToId[rowIdx]), { verdict: v.v === 'R' ? 'RESUB' : 'NEW', confidence: v.c ?? 0, reason: v.r || null });
        }
      }
      console.log(`[ReSubAI] Chunk ${Math.floor(i / CHUNK_SIZE) + 1}: ${resultMap.size} resolved`);
    } catch (err) { console.warn('[ReSubAI] Groq chunk error:', err.message); }
  }
  return resultMap;
}

async function groqDeepScan(targets) {
  if (!targets.length) return new Map();
  if (resubGroqLimiter.isCooling()) { console.log('[DeepScan] Cooling'); return new Map(); }
  const GROQ_KEY = process.env.GROQ_API_KEY || process.env.GROQ_API_KEY_FALLBACK;
  if (!GROQ_KEY) return new Map();
  const CHUNK_SIZE = 8;
  const resultMap = new Map();
  for (let i = 0; i < targets.length; i += CHUNK_SIZE) {
    const chunk = targets.slice(i, i + CHUNK_SIZE);
    const idxToId = chunk.map(t => t.id);
    if (resubGroqLimiter.isCooling()) break;
    await resubGroqLimiter.wait();
    const rows = chunk.map((t, ci) => {
      const cands = (t.topCandidates || []).slice(0, 3).map(c => `${c.name.slice(0, 22)}(${c.score}%)`).join(' ') || '-';
      return `${ci + 1}:${t.cleanedNom.slice(0, 25)}→${cands}`;
    }).join('\n');
    const prompt = `DEEP SCAN mode. Moroccan gym members classified as NEW but may be RESUB.\nBe PROACTIVE: name written differently, phonetic misspelling, partial entry, different order.\nRules:\n- Same first name but completely different family name → N\n- Same family name but DISTINCT first names (siblings) → N\n- ANY unique token phonetic match → strong signal\n- Family-only \"EL ALAOUI\" matches \"YOUSSEF EL ALAOUI\" → R (only if first name absent)\n- Score 50%+ with structural/phonetic resemblance → RESUB\n\nRows (NUM:NEW_NAME→ODOO_CANDIDATES):\n${rows}\n\nReply ONLY: [{"n":<NUM>,"v":"R or N","c":<0-100>,"r":"<5 words French>"}]`;
    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'llama-3.1-8b-instant', messages: [{ role: 'user', content: prompt }], temperature: 0.1, max_tokens: Math.min(chunk.length * 40 + 60, 400) }),
      });
      if (r.status === 413) continue;
      if (r.status === 429) { resubGroqLimiter.trigger429(); break; }
      if (!r.ok) continue;
      const data = await r.json();
      const text = data.choices?.[0]?.message?.content?.trim() || '';
      let verdicts = [];
      const arrMatch = text.match(/\[[\s\S]*?\]/);
      if (arrMatch) { try { verdicts = JSON.parse(arrMatch[0]); } catch (_) {} }
      for (const v of verdicts) {
        const rowIdx = (v?.n ?? 0) - 1;
        if (rowIdx >= 0 && rowIdx < chunk.length) {
          const isResub = v.v === 'R' && (v.c ?? 0) >= 60;
          resultMap.set(String(idxToId[rowIdx]), { verdict: isResub ? 'RESUB' : 'NEW', confidence: v.c ?? 0, reason: v.r || null });
        }
      }
    } catch (err) { console.warn('[DeepScan] Error:', err.message); }
  }
  return resultMap;
}

module.exports = {
  CLUB_TO_GYM, GYM_TO_CLUB,
  cleanName, findBestMatch,
  groqBatchValidate, groqDeepScan, resubGroqLimiter,
  loadOdooCSV,
};
