'use strict';
// routes/commercials.js — Commercial Performance, Goals & Re-Sub Intelligence

const { Router } = require('express');
const fs   = require('fs');
const path = require('path');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

// ─────────────────────────────────────────────────────────────────────────────
// ★ RE-SUB INTELLIGENCE ENGINE (module-level singleton, parsed once)
// Optimised: CSV parsed on first call, then cached in-memory for instant reuse.
// Uses bigram index for O(k) candidate pre-filter before Levenshtein on top-N.
// ─────────────────────────────────────────────────────────────────────────────

const ODOO_CSV_PATH = path.join(__dirname, '../odoo/all_members_all_clubs.csv');

// Club name → gym_id mapping
const CLUB_TO_GYM = {
  'FES DOUKKARATE': 'dokarat',
  'FES MARJANE':    'marjane',
  'CASA ANFA':      'casa1',
  'CASA ANFA LADY': 'casa2',
};
const GYM_TO_CLUB = Object.fromEntries(Object.entries(CLUB_TO_GYM).map(([k,v])=>[v,k]));

// Cache: { members: Array, bigramIndex: Map<bigram→Set<idx>>, loadedAt: number }
let _csvCache = null;

// Performance Cache: { map: Map<cleanName → birthday>, loadedAt: number }
let _bdayCache = null;

// Name Cleaning Cache (Memoization)
const _cleanNameCache = new Map();

/** Remove emojis, extra whitespace, accents → clean uppercase token */
// ─────────────────────────────────────────────────────────────────────────────
// ★ MOROCCAN NAME INTELLIGENCE
// Handles two common Moroccan data issues:
//   1. Concatenated names with no space: "KARIMSKOURI" → "KARIM SKOURI"
//   2. Family-name-only entries (matched via partial search)
// ─────────────────────────────────────────────────────────────────────────────

// Comprehensive Moroccan/Arabic first name dictionary (male + female, common variants)
const MOROCCAN_FIRST_NAMES = new Set([
  // Male
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
  'RYAN','RIDA','LOUBNA','LOUBNA','LHOUSSAINE','LAHCEN','LARBI','LHOUCINE',
  'EL','BEN','AIT','ABI','BNOU','BENT',
  // Female
  'FATIMA','KHADIJA','ZINEB','SARA','SARAH','LAYLA','LEILA','HAJAR','SOUKAINA',
  'NADIA','IMANE','HANAE','SANAE','MERIEM','MERYEM','ASMAA','ASMA','AMINA','AMINE',
  'SIHAM','HOUDA','HODA','WIDAD','WIDAD','CHAIMA','CHAIMAE','OUMAIMA','MARIAM','MARYAM',
  'NAJAT','NAJET','NABILA','NOURA','NORA','NISRINE','NIHAL','MALAK','MANAL','MANEL',
  'HIND','HANA','HANANE','GHITA','GHIZLANE','GHIZLAN','FADWA','FATINE','FATIHA',
  'DOUNIA','DOHA','CHADIA','CHAMA','BTISSAM','BOUCHRA','BADREDDINE','BADR','BASMA',
  'AHLAM','AICHA','AISHA','ABIR','SAMIRA','SABRINE','SABRINA','SALWA','SAFAA','SAFA',
  'RAJAE','RAJAAE','RABAB','RANIA','RANYA','RHIMOU','LATIFA','LAMYAE','LAMIAE',
  'LOUBNA','LUBNA','LINA','LENA','IKRAM','INSAF','INTISSAR','ILHAM',
  'YOUSSRA','YOUSRA','YOUSSEF','WISSAL','WISSAL','WAFAA','WAFA',
]);

/** Remove emojis, extra whitespace, accents → clean uppercase token */
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
  
  if (_cleanNameCache.size > 20000) _cleanNameCache.clear(); // Safety cap
  _cleanNameCache.set(raw, cleaned);
  return cleaned;
}

/**
 * Attempt to insert a missing space into a Moroccan name.
 * "KARIMSKOURI" → "KARIM SKOURI" (detected because KARIM is a known first name prefix)
 * Returns the split version, or the original if no split found.
 */
function splitMoroccanName(name) {
  if (name.includes(' ') || name.length < 6) return name;  // already spaced or too short

  // Try every known first name as a prefix
  for (const fn of MOROCCAN_FIRST_NAMES) {
    if (fn.length >= 3 && name.startsWith(fn) && name.length > fn.length) {
      const rest = name.slice(fn.length);
      if (rest.length >= 3) return `${fn} ${rest}`;
    }
  }

  // Try suffix: family name first, then first name
  for (const fn of MOROCCAN_FIRST_NAMES) {
    if (fn.length >= 3 && name.endsWith(fn) && name.length > fn.length) {
      const rest = name.slice(0, name.length - fn.length);
      if (rest.length >= 3) return `${rest} ${fn}`;
    }
  }

  return name;  // No split found
}

/** Extract bigrams from a string for fast pre-filtering */
function bigrams(str) {
  const s = str.replace(/\s+/g, '');
  const out = new Set();
  for (let i = 0; i < s.length - 1; i++) out.add(s.slice(i, i + 2));
  return out;
}

/** Levenshtein distance (optimised row-buffer, early-exit at maxDist) */
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

/** Similarity ratio 0–100 */
function similarity(a, b) {
  if (!a || !b) return 0;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 100;
  return Math.round((1 - levenshtein(a, b, maxLen) / maxLen) * 100);
}

/**
 * TOKEN-AWARE similarity — prevents single-token (first-name-only) false positives.
 * Example: "HADINE NAIMA" vs "FATIHA NAIMA ZARHBOUCH"
 *   Both share NAIMA, but HADINE≠FATIHA and ZARHBOUCH has no match → capped score.
 * Rules:
 *  - If source has 2+ tokens AND only ONE token matches well (≥70) while the other is poor (<50),
 *    the score is hard-capped at 55 to flag it as NOT a reliable match.
 *  - Combined token score = best×0.60 + second×0.40.
 *  - Takes the max of combined vs full-string similarity (preserves exact matches).
 */
function tokenAwareSimilarity(queryClean, memberClean) {
  const qTokens = queryClean.split(' ').filter(t => t.length >= 2);
  const mTokens = memberClean.split(' ').filter(t => t.length >= 2);

  // Single-token names: fall back to plain string similarity
  if (qTokens.length < 2 || mTokens.length < 2) {
    return similarity(queryClean, memberClean);
  }

  // For each query token, find its best match among master tokens
  const tokenScores = qTokens.map(qt =>
    Math.max(...mTokens.map(mt => similarity(qt, mt)))
  );
  tokenScores.sort((a, b) => b - a);

  const best   = tokenScores[0] || 0;
  const second = tokenScores[1] || 0;

  // CRITICAL: single-token coincidence trap (e.g. shared first name only)
  if (best >= 70 && second < 50) {
    return Math.min(55, best - 20); // not a reliable match
  }

  const combined = Math.round(best * 0.60 + second * 0.40);
  const fullSim  = similarity(queryClean, memberClean);
  return Math.max(combined, fullSim);
}

/** Load & index CSV once, return cache */
function loadOdooCSV() {
  if (_csvCache) return _csvCache;

  console.log('📂 [ReSubEngine] Loading Odoo CSV…');
  let raw;
  try { raw = fs.readFileSync(ODOO_CSV_PATH, 'utf-8'); }
  catch (e) { console.error('❌ [ReSubEngine] CSV not found:', e.message); _csvCache = { members: [], bigramIndex: new Map() }; return _csvCache; }

  const lines   = raw.split('\n').slice(1);
  const members = [];
  const bigramIndex = new Map();

  for (const line of lines) {
    if (!line.trim()) continue;
    const cols      = line.split(',');
    const full_name = cols[0]?.trim();
    const club      = cols[6]?.trim();
    const status    = cols[7]?.trim();
    const subs_stop = cols[9]?.trim();
    const last_pay  = cols[11]?.trim();
    const x_birthday= cols[12]?.trim();
    if (!full_name || !club) continue;

    const cleaned = cleanName(full_name);
    const idx     = members.length;
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

/**
 * Run a bigram + Levenshtein search for one cleaned name variant.
 * Returns { bestScore, bestMember, candidateIdxs }
 */
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

/**
 * Find best match for a query name in the Odoo CSV.
 * Tries original name + space-split Moroccan variant, takes the best.
 */
function findBestMatch(queryName) {
  const { members, bigramIndex } = loadOdooCSV();
  if (!members.length) return null;

  const cleaned = cleanName(queryName);

  // ── Variant 1: original cleaned name ─────────────────────────────────────
  const v1 = _searchVariant(cleaned, members, bigramIndex);

  // ── Variant 2: Moroccan name split (e.g. "KARIMSKOURI" → "KARIM SKOURI") ─
  const split   = splitMoroccanName(cleaned);
  const v2      = split !== cleaned ? _searchVariant(split, members, bigramIndex) : { bestScore: 0, bestMember: null, candidates: [] };

  // Pick the winner
  const best       = v2.bestScore > v1.bestScore ? v2 : v1;
  const bestCands  = v2.bestScore > v1.bestScore ? v2.candidates : v1.candidates;
  const usedName   = v2.bestScore > v1.bestScore ? split : cleaned;

  // Top-5 candidates for Groq (deduped, sorted by score)
  const seen = new Set();
  const topCandidates = [...v1.candidates, ...v2.candidates]
    .filter(idx => { if (seen.has(idx)) return false; seen.add(idx); return true; })
    .slice(0, 8)
    .map(idx => ({
      name:       members[idx].cleaned,
      full_name:  members[idx].full_name,
      club:       members[idx].club,
      gymId:      members[idx].gymId,
      status:     members[idx].status,
      subs_stop:  members[idx].subs_stop,
      x_birthday: members[idx].x_birthday,
      score:      tokenAwareSimilarity(usedName, members[idx].cleaned)
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 4);

  return {
    match:         best.bestMember?.full_name || null,
    score:         best.bestScore,
    prevClub:      best.bestMember?.club || null,
    prevGymId:     best.bestMember?.gymId || null,
    status:        best.bestMember?.status || null,
    lastSub:       best.bestMember?.subs_stop || null,
    usedVariant:   usedName,         // what we actually matched on (for debug)
    wasSplit:      usedName !== cleaned,  // true if a space was auto-inserted
    topCandidates,
  };
}


// ─────────────────────────────────────────────────────────────────────────────
// ★ GROQ BATCH AI VALIDATOR

// Sends all POSSIBLE-tier cases (fuzzy 70-84%) to Groq in ONE batched call.
// CERTAIN cases (>=85 or <70) bypass Groq entirely — saves tokens & latency.
// ─────────────────────────────────────────────────────────────────────────────

const resubGroqLimiter = {
  lastCall:      0,
  cooldownUntil: 0,
  minGapMs:      4000,
  cooldownMs:    60000,
  isCooling()  { return Date.now() < this.cooldownUntil; },
  trigger429() { this.cooldownUntil = Date.now() + this.cooldownMs; console.warn('[ReSubAI] 429 — cooling 60s'); },
  async wait() {
    const gap = this.minGapMs - (Date.now() - this.lastCall);
    if (gap > 0) await new Promise(r => setTimeout(r, gap));
    this.lastCall = Date.now();
  },
};

async function groqBatchValidate(possibles) {
  if (!possibles.length) return new Map();
  if (resubGroqLimiter.isCooling()) {
    console.log('[ReSubAI] Groq in cooldown — fuzzy-only for ambiguous cases');
    return new Map();
  }

  const GROQ_KEY = process.env.GROQ_API_KEY || process.env.GROQ_API_KEY_FALLBACK;
  if (!GROQ_KEY) return new Map();

  // KEY FIX for 413: use 1-based numeric index in prompt — NOT Firebase 20-char IDs
  // Saves ~20 chars × 8 cases = 160 chars per chunk. Map back after response.
  const CHUNK_SIZE = 8;
  const resultMap  = new Map();

  for (let i = 0; i < possibles.length; i += CHUNK_SIZE) {
    const chunk    = possibles.slice(i, i + CHUNK_SIZE);
    const idxToId  = chunk.map(p => p.id);  // 0-based → real DB id

    if (resubGroqLimiter.isCooling()) { console.log('[ReSubAI] Cooling — skip remaining'); break; }
    await resubGroqLimiter.wait();

    // Ultra-compact: "1:NEWNAME→CAND1(85%)CAND2(79%)"
    const rows = chunk.map((p, ci) => {
      const cands = (p.topCandidates || []).slice(0, 2)
        .map(c => `${c.name.slice(0, 20)}(${c.score}%)`)
        .join(' ') || '-';
      return `${ci + 1}:${p.cleanedNom}→${cands}`;
    }).join('\n');

    const prompt = `You are a senior data-quality engineer specialized in Moroccan identity reconciliation.
Task: Match SOURCE inscriptions to MASTER (ODOO) candidates.

Rules:
-Normalize: Mohamed/Mohammed/Med, Ahmed/Ahmad, Yassine/Yassin, Zakaria/Zakarya, Chaimae/Chaimaa, Abdelilah/Abdellah, etc.
-Particles: EL, AL, BEN, BENT, IBN, OULD, AIT, SIDI (ignore or match as prefixes).
-Names: FIRST LAST = LAST FIRST. Reversed tokens match.
-Strictness: If family name structure differs even slightly (AZZOUNE vs MEZZOUNOU, ABDELALI vs ALKALAMI) -> N (NEW).
-Doubt: Confidence < 88% with different club/tokens -> P (POSSIBLE) or N.
-Score < 75% -> N.

Rows (NUM:NEW→ODOO_MATCHES):
${rows}

Reply ONLY: [{"n":<NUM>,"v":"R(RESUB), N(NEW) or P(POSSIBLE)","c":<0-100>,"r":"<5 words raison audit>"}]`;

    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama-3.1-8b-instant',
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.05,
          max_tokens: Math.min(chunk.length * 40 + 60, 400),
        }),
      });

      if (r.status === 413) { console.warn('[ReSubAI] 413 still — chunk too large, skip'); continue; }
      if (r.status === 429) { resubGroqLimiter.trigger429(); break; }
      if (!r.ok) { console.warn('[ReSubAI] Groq HTTP', r.status); continue; }

      const data  = await r.json();
      const text  = data.choices?.[0]?.message?.content?.trim() || '';
      let verdicts = [];
      const arrMatch = text.match(/\[[\s\S]*?\]/);
      if (arrMatch) { try { verdicts = JSON.parse(arrMatch[0]); } catch (_) {} }

      let resolved = 0;
      for (const v of verdicts) {
        const rowIdx = (v?.n ?? v?.num ?? 0) - 1;  // 1-based → 0-based
        if (rowIdx >= 0 && rowIdx < chunk.length) {
          resultMap.set(String(idxToId[rowIdx]), {
            verdict:    v.v === 'R' ? 'RESUB' : 'NEW',
            confidence: v.c ?? 0,
            reason:     v.r || null,
          });
          resolved++;
        }
      }
      console.log(`[ReSubAI] Chunk ${Math.floor(i / CHUNK_SIZE) + 1}: ${resolved}/${chunk.length} resolved by AI`);
    } catch (err) {
      console.warn('[ReSubAI] Groq chunk error:', err.message);
    }
  }

  console.log(`[ReSubAI] ✅ Total AI-validated: ${resultMap.size}/${possibles.length}`);
  return resultMap;
}


// ─────────────────────────────────────────────────────────────────────────────
// ★ GROQ DEEP SCAN — Second pass AI for hidden RESUB detection
// Targets NEW members with fuzzy score 40-69% (the "uncertain" zone).
// Uses a broader, more permissive prompt focused on:
//   - Partial family name matches (EL ALAOUI matches ALAOUI)
//   - Single-word names matching part of a full name
//   - High-confidence name variants missed by Levenshtein
// ─────────────────────────────────────────────────────────────────────────────
async function groqDeepScan(targets) {
  if (!targets.length) return new Map();
  if (resubGroqLimiter.isCooling()) {
    console.log('[DeepScan] Rate limiter cooling — deferring');
    return new Map();
  }

  const GROQ_KEY = process.env.GROQ_API_KEY || process.env.GROQ_API_KEY_FALLBACK;
  if (!GROQ_KEY) return new Map();

  const CHUNK_SIZE = 8;
  const resultMap  = new Map();

  for (let i = 0; i < targets.length; i += CHUNK_SIZE) {
    const chunk   = targets.slice(i, i + CHUNK_SIZE);
    const idxToId = chunk.map(t => t.id);

    if (resubGroqLimiter.isCooling()) { console.log('[DeepScan] Cooling — pausing'); break; }
    await resubGroqLimiter.wait();

    const rows = chunk.map((t, ci) => {
      const cands = (t.topCandidates || []).slice(0, 3)
        .map(c => `${c.name.slice(0, 22)}(${c.score}%)`)
        .join(' ') || '-';
      return `${ci + 1}:${t.cleanedNom.slice(0, 25)}→${cands}`;
    }).join('\n');

    // Deep scan: broader, more permissive — actively looking for hidden matches
    const prompt = `DEEP SCAN mode. You are analyzing Moroccan gym members who were classified as NEW (no match found) but may actually be returning members (RESUB) with hard-to-match names.

Be PROACTIVE — these are exactly the cases where the name was:
- Written very differently (missing prefix EL/BEN/AIT like LAFOUTAH = EL AFOUITTAH)
- Phonetically misspelled (ZOUITNI = ZUITNI, MOUNIM = MOUMIN)
- Partially entered (family name only, no first name)
- In different order or severely shortened
- Contain phone typos or concatenated tokens

Rules:
- Same first name but completely different family name (e.g. ADDIDI != FADILI) → N (Must not match!)
- Same family name but DISTINCT first names, especially male vs female (e.g. ISMAIL vs ASMAE) → N (These are siblings/relatives, do NOT match!)
- If ANY unique token in the new name matches phonetically → strong signal
- Family-only "EL ALAOUI" matches "YOUSSEF EL ALAOUI" → R (ONLY if the first name is completely absent)
- Score 50%+ with any structural/phonetic resemblance → RESUB
- Complete gibberish or very short common names → NEW

Rows (NUM:NEW_NAME→ODOO_CANDIDATES with fuzzy scores):
${rows}

Reply ONLY: [{"n":<NUM>,"v":"R or N","c":<0-100>,"r":"<5 words French>"}]
(R=RESUB=hidden returning member, N=confirmed NEW)`;

    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model:       'llama-3.1-8b-instant',
          messages:    [{ role: 'user', content: prompt }],
          temperature: 0.1,   // slightly higher — allow more inference on ambiguous cases
          max_tokens:  Math.min(chunk.length * 40 + 60, 400),
        }),
      });

      if (r.status === 413) { console.warn('[DeepScan] 413 — skip chunk'); continue; }
      if (r.status === 429) { resubGroqLimiter.trigger429(); break; }
      if (!r.ok) { console.warn('[DeepScan] Groq HTTP', r.status); continue; }

      const data     = await r.json();
      const text     = data.choices?.[0]?.message?.content?.trim() || '';
      let verdicts   = [];
      const arrMatch = text.match(/\[[\s\S]*?\]/);
      if (arrMatch) { try { verdicts = JSON.parse(arrMatch[0]); } catch (_) {} }

      let found = 0;
      for (const v of verdicts) {
        const rowIdx = (v?.n ?? 0) - 1;
        if (rowIdx >= 0 && rowIdx < chunk.length) {
          const isResub = v.v === 'R' && (v.c ?? 0) >= 60;  // confidence threshold for upgrades
          resultMap.set(String(idxToId[rowIdx]), {
            verdict:    isResub ? 'RESUB' : 'NEW',
            confidence: v.c ?? 0,
            reason:     v.r || null,
          });
          if (isResub) found++;
        }
      }
      console.log(`[DeepScan] Chunk ${Math.floor(i / CHUNK_SIZE) + 1}: ${found} hidden RESUB found in ${chunk.length} cases`);
    } catch (err) {
      console.warn('[DeepScan] Error:', err.message);
    }
  }

  return resultMap;
}




module.exports = function commercialsRouter({ db, admin, lc }) {
  const router = Router();

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/commercials/stats?gymId=dokarat&month=2026-04
  // Reads from SQLite register_cache — zero Firestore reads
  // Returns per-commercial revenue, inscription count, daily breakdown
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/stats', verifyAzureToken, (req, res) => {
    try {
      const { gymId = 'dokarat', month, startDate, endDate } = req.query;

      // Support either a custom date range OR a month (YYYY-MM)
      const useRange = startDate && endDate;
      const now    = new Date();
      const target = month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : gymId.split(',').map(s => s.trim());

      const placeholders = gymIds.map(() => '?').join(',');

      // Build WHERE date clause — range or month prefix
      const dateWhere = useRange
        ? `date >= ? AND date <= ?`
        : `date LIKE ?`;
      const dateArgs  = useRange
        ? [startDate, endDate]
        : [`${target}%`];

      const rows = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial))  AS commercial,
          gym_id,
          COUNT(*)                 AS inscriptions,
          SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) AS revenue,
          MIN(date)                AS first_sale,
          MAX(date)                AS last_sale
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND ${dateWhere}
        GROUP BY UPPER(TRIM(commercial)), gym_id
        ORDER BY revenue DESC
      `).all(...gymIds, ...dateArgs);

      // Daily breakdown per commercial — normalized
      const daily = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial))  AS commercial,
          gym_id,
          date,
          COUNT(*)   AS count,
          SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC))  AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND ${dateWhere}
        GROUP BY UPPER(TRIM(commercial)), gym_id, date
        ORDER BY date ASC
      `).all(...gymIds, ...dateArgs);

      // ── Alias / typo normalization map ────────────────────────────────────
      // Key = any known variant (already UPPER-TRIMMED), Value = official name
      const CANONICAL = {
        'HAJARE':   'HAJAR',
        'OUISSALE': 'OUISSALE',
        'IMANE':    'IMANE',
        'REDA':     'REDA',
        'ZINEB':    'ZINEB',
        'SABER':    'SABER',
        'AHLALM':   'AHLAM',
      };
      
      function canonical(name) {
        let up = (name || '').trim().toUpperCase();
        
        // Group all empty, dash, or hidden system sales into one visible "AUTRE" category
        if (!up || up === '-' || up === 'NULL' || up.includes('@') || up.startsWith('MR') || ['OFFERT','GRATUIT','TEST','SYSTEM'].includes(up)) {
           return 'AUTRE (SANS NOM)';
        }
        
        return CANONICAL[up] || up; // keep as-is if not in map
      }

      // Build daily map — keyed by canonical name
      const dailyMap = {};
      daily.forEach(r => {
        const key = canonical(r.commercial);
        if (!dailyMap[key]) dailyMap[key] = [];
        dailyMap[key].push({ date: r.date, count: r.count, revenue: r.revenue });
      });

      // Build per-canonical aggregation (merge alias rows)
      const merged = {};
      rows.forEach(r => {
        const name = canonical(r.commercial);
        if (!merged[name]) {
          merged[name] = { name, gymId: r.gym_id, inscriptions: 0, revenue: 0, firstSale: r.first_sale, lastSale: r.last_sale };
        }
        merged[name].inscriptions += r.inscriptions || 0;
        merged[name].revenue      += Math.round(r.revenue || 0);
        // keep earliest firstSale and latest lastSale across aliases
        if (!merged[name].firstSale || r.first_sale < merged[name].firstSale) merged[name].firstSale = r.first_sale;
        if (!merged[name].lastSale  || r.last_sale  > merged[name].lastSale)  merged[name].lastSale  = r.last_sale;
      });

      const stats = Object.values(merged)
        .map(c => ({ ...c, daily: dailyMap[c.name] || [] }))
        .sort((a, b) => b.revenue - a.revenue);

      // ✅ Subtract approved décaissements from gross total (same rule as KPI + Register)
      let totalDecaissements = 0;
      gymIds.forEach(gid => {
        const daysInMonth = new Date(target.split('-')[0], target.split('-')[1], 0).getDate();
        for (let d = 1; d <= daysInMonth; d++) {
          const dateStr = `${target}-${String(d).padStart(2,'0')}`;
          const decs = lc.getDecaissements(gid, dateStr) || [];
          decs.filter(dec => dec.status === 'approved' || !dec.status)
              .forEach(dec => { totalDecaissements += Number(dec.montant) || 0; });
        }
      });

      const rosterRows = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial)) AS commercial,
          MAX(date) AS last_sale
        FROM register_cache
        WHERE gym_id IN (${placeholders})
        GROUP BY UPPER(TRIM(commercial))
      `).all(...gymIds);
      
      const rosterMap = {};
      rosterRows.forEach(r => {
         const name = canonical(r.commercial);
         if (!rosterMap[name] || r.last_sale > rosterMap[name].lastSale) {
            rosterMap[name] = { name, lastSale: r.last_sale };
         }
      });
      const roster = Object.values(rosterMap).sort((a,b) => b.lastSale.localeCompare(a.lastSale));

      res.json({ ok: true, month: target, stats, roster });
    } catch (err) {
      console.error('GET /api/commercials/stats error:', err);
      res.status(500).json({ error: 'Erreur lors de la récupération des stats' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/commercials/goals?gymId=dokarat
  // Public read (authenticated) — managers can see too
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/goals', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat' } = req.query;
      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : gymId.split(',').map(s => s.trim());

      // Include 'all' so global goals show up for specific gyms
      const searchGymIds = gymId === 'all' ? [...gymIds, 'all'] : [...gymIds, 'all'];

      const snap = await db.collection('commercial_goals')
        .where('gymId', 'in', searchGymIds)
        .get();
        
      const goals = snap.docs
        .map(d => ({ id: d.id, ...d.data() }))
        .sort((a, b) => (b.period || '').localeCompare(a.period || ''));

      // Dynamically calculate the actual real-time revenue for the Gym and Period
      // This includes ALL commercials (even unspecified or dashes) so the Challenge matches the Register Total perfectly!
      for (let g of goals) {
        // Support both legacy period (YYYY-MM) and custom date range (startDate/endDate)
        const hasRange = g.startDate && g.endDate;
        if (!hasRange && !g.period) {
          g.currentRevenue = 0; g.currentInscriptions = 0; continue; 
        }
        
        let targetGyms = g.gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : [g.gymId];
        const placeholders = targetGyms.map(() => '?').join(',');
        
        const dateWhere = hasRange
          ? `date >= ? AND date <= ?`
          : `date LIKE ?`;
        const dateArgs  = hasRange
          ? [g.startDate, g.endDate]
          : [`${g.period}%`];

        const stats = lc.db.prepare(`
          SELECT 
            COUNT(*) as inscriptions, 
            SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as revenue 
          FROM register_cache 
          WHERE gym_id IN (${placeholders}) AND ${dateWhere}
        `).get(...targetGyms, ...dateArgs);
        
        g.currentRevenue = Math.round(stats?.revenue || 0);
        g.currentInscriptions = stats?.inscriptions || 0;
      }

      res.json({ ok: true, goals });
    } catch (err) {
      console.error('GET /api/commercials/goals error:', err);
      res.status(500).json({ error: 'Erreur lors de la récupération des objectifs' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // POST /api/commercials/goals — Super Admin only
  // Body: { gymId, period, targetRevenue, targetInscriptions, reward, label }
  // ─────────────────────────────────────────────────────────────────────────────
  router.post('/goals', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, period, startDate, endDate, targetRevenue, targetInscriptions, reward, label, challengeType } = req.body;
      // Either period (monthly) or startDate+endDate (custom range) required
      if (!gymId) return res.status(400).json({ error: 'gymId est obligatoire' });
      if (challengeType === 'range' && (!startDate || !endDate)) return res.status(400).json({ error: 'startDate et endDate obligatoires pour un défi libre' });
      if (challengeType !== 'range' && !period) return res.status(400).json({ error: 'period obligatoire pour un défi mensuel' });

      const doc = {
        gymId,
        challengeType: challengeType || 'month',  // 'month' | 'range'
        period:        challengeType === 'range' ? null : period,
        startDate:     challengeType === 'range' ? startDate : null,
        endDate:       challengeType === 'range' ? endDate   : null,
        label:         label || (challengeType === 'range' ? `${startDate} → ${endDate}` : period),
        targetRevenue:      Number(targetRevenue) || 0,
        targetInscriptions: Number(targetInscriptions) || 0,
        reward:        reward || '',
        createdBy:     req.user?.preferred_username || 'Admin',
        createdAt:     admin.firestore.FieldValue.serverTimestamp(),
        active:        true,
      };

      const ref = await db.collection('commercial_goals').add(doc);
      res.json({ ok: true, id: ref.id, goal: doc });
    } catch (err) {
      console.error('POST /api/commercials/goals error:', err);
      res.status(500).json({ error: 'Erreur lors de la création de l\'objectif' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // PATCH /api/commercials/goals/:id — Super Admin only
  // ─────────────────────────────────────────────────────────────────────────────
  router.patch('/goals/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const updates = req.body;
      delete updates.createdAt; delete updates.createdBy;
      await db.collection('commercial_goals').doc(req.params.id).update(updates);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Erreur lors de la mise à jour' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // DELETE /api/commercials/goals/:id — Super Admin only
  // ─────────────────────────────────────────────────────────────────────────────
  router.delete('/goals/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('commercial_goals').doc(req.params.id).delete();
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Erreur lors de la suppression' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/sales/multi-stats?gymId=dokarat&months=6
  // Returns per-commercial stats for each of the last N months
  // Used by the Commercial Performance Matrix in Auralix
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/multi-stats', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat', months: monthsParam = '6' } = req.query;
      const N = Math.min(parseInt(monthsParam) || 6, 12);

      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : gymId.split(',').map(s => s.trim());
      const placeholders = gymIds.map(() => '?').join(',');

      // Build list of last N month strings (YYYY-MM)
      const now = new Date();
      const monthList = [];
      for (let i = N - 1; i >= 0; i--) {
        const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
        monthList.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`);
      }

      // Alias normalization (same as stats endpoint)
      const CANONICAL = { 'HAJARE':'HAJAR','AHLALM':'AHLAM' };
      function canonical(name) {
        let up = (name || '').trim().toUpperCase();
        if (!up || up==='-' || up.includes('@') || up.startsWith('MR') || ['OFFERT','GRATUIT','TEST','SYSTEM','NULL'].includes(up)) return null;
        return CANONICAL[up] || up;
      }

      // Fetch all rows across all N months in one query
      const firstMonth = monthList[0];
      const lastMonth  = monthList[monthList.length - 1];

      const rows = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial)) AS commercial,
          substr(date, 1, 7)       AS month,
          COUNT(*)                 AS inscriptions,
          SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date >= ? AND date <= ?
        GROUP BY UPPER(TRIM(commercial)), substr(date, 1, 7)
        ORDER BY month ASC
      `).all(...gymIds, `${firstMonth}-01`, `${lastMonth}-31`);

      // Build matrix: { commercial -> { month -> {revenue, inscriptions} } }
      const matrix = {};
      const gymTotals = {};
      monthList.forEach(m => { gymTotals[m] = { revenue: 0, inscriptions: 0 }; });

      rows.forEach(r => {
        const name = canonical(r.commercial);
        if (!name || !monthList.includes(r.month)) return;
        if (!matrix[name]) matrix[name] = {};
        matrix[name][r.month] = { revenue: Math.round(r.revenue || 0), inscriptions: r.inscriptions || 0 };
        gymTotals[r.month].revenue      += Math.round(r.revenue || 0);
        gymTotals[r.month].inscriptions += r.inscriptions || 0;
      });

      // Compute per-commercial totals
      const commercials = Object.entries(matrix).map(([name, perMonth]) => {
        const totalRevenue      = Object.values(perMonth).reduce((s, m) => s + m.revenue, 0);
        const totalInscriptions = Object.values(perMonth).reduce((s, m) => s + m.inscriptions, 0);
        return { name, perMonth, totalRevenue, totalInscriptions };
      }).sort((a, b) => b.totalRevenue - a.totalRevenue);

      // Fetch goals for those months for goal vs actual comparison
      const snap = await db.collection('commercial_goals')
        .where('gymId', 'in', [...gymIds, 'all'])
        .get();
      const goals = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      res.json({ ok: true, months: monthList, commercials, gymTotals, goals });
    } catch (err) {
      console.error('GET /api/sales/multi-stats error:', err);
      res.status(500).json({ error: err.message });
    }
  });



  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/sales/resub-matrix?gymId=dokarat&month=2026-05
  // AI-powered Re-Sub vs New Member classification matrix.
  // Uses bigram pre-filter + Levenshtein fuzzy match against 12k Odoo records.
  // CSV is parsed & indexed once in memory — subsequent calls are fast.
  //
  // Classifications:
  //   RESUB    (score ≥ 85) — high-confidence returning member
  //   POSSIBLE (score 70-84) — likely returning, flagged for review
  //   NEW      (score < 70) — first-time member
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/resub-matrix', verifyAzureToken, async (req, res) => {
    try {
      // Supports:
      //   ?month=2026-05          (single month, legacy)
      //   ?startMonth=2026-04&endMonth=2026-05  (multi-month range)
      //   ?months=3               (last N months from today)
      const { gymId = 'dokarat', month, startMonth, endMonth, months: monthsParam } = req.query;
      const now = new Date();

      let startDate, endDate, dateLabel;

      if (startMonth && endMonth) {
        // Explicit range
        startDate  = `${startMonth}-01`;
        endDate    = `${endMonth}-31`;
        dateLabel  = `${startMonth} → ${endMonth}`;
      } else if (monthsParam) {
        // Last N months
        const N = Math.min(parseInt(monthsParam) || 2, 12);
        const fromDate = new Date(now.getFullYear(), now.getMonth() - (N - 1), 1);
        const fromMo   = `${fromDate.getFullYear()}-${String(fromDate.getMonth() + 1).padStart(2, '0')}`;
        const toMo     = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
        startDate  = `${fromMo}-01`;
        endDate    = `${toMo}-31`;
        dateLabel  = `${fromMo} → ${toMo}`;
      } else {
        // Single month (default: current)
        const target = month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
        startDate = `${target}-01`;
        endDate   = `${target}-31`;
        dateLabel = target;
      }

      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : gymId.split(',').map(s => s.trim());

      const placeholders = gymIds.map(() => '?').join(',');

      // Fetch all inscriptions in the date range across selected gyms
      const rows = lc.db.prepare(`
        SELECT id, gym_id, nom, date, abonnement, tel, cin,
               (tpe + espece + virement + cheque) AS total
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date >= ? AND date <= ?
        ORDER BY date DESC
      `).all(...gymIds, startDate, endDate);

      // Pre-warm CSV index (fast after first call)
      loadOdooCSV();

      const NOW_ISO = new Date().toISOString();

      // ── PASS 0: Load cached verdicts from SQLite ──────────────────────────
      // Key: register_id (PRIMARY KEY) — one row per inscription, ever.
      const cachedRows = lc.db.prepare(`
        SELECT register_id, type, confidence, matched_name, prev_club, prev_gym_id,
               prev_status, last_sub, ai_verified, ai_reason, detection_mode,
               used_variant, was_split
        FROM resub_intelligence_cache
        WHERE register_id IN (${rows.map(() => '?').join(',')})
      `).all(...rows.map(r => String(r.id)));

      const cacheMap = new Map(cachedRows.map(c => [String(c.register_id), c]));
      console.log(`[ReSubCache] ${cacheMap.size}/${rows.length} inscriptions already cached`);

      // ── PRE-PASS: Load all known birthdays from local Firebase members ──────
      // This maps normalized names to their birthday string (e.g. "1994-04-05")
      // ── BIRTHDAY DICTIONARY CACHE ──────────────────────────────────────────
      // Optimization: Load birthdays once per request or use memoized map
      if (!_bdayCache || (Date.now() - _bdayCache.loadedAt > 300000)) { // 5 min TTL
        const localBirthdays = new Map();
        const bdayRows = lc.db.prepare("SELECT full_name, birthday FROM members_cache WHERE birthday IS NOT NULL AND birthday != ''").all();
        for (const b of bdayRows) {
          const key = cleanName(b.full_name);
          if (key) localBirthdays.set(key, b.birthday);
        }
        _bdayCache = { map: localBirthdays, loadedAt: Date.now() };
        console.log(`[ReSubAI] Cached ${localBirthdays.size} local birthdays for matching`);
      }
      const localBirthdays = _bdayCache.map;

      // ── PASS 1: Fuzzy classify ONLY uncached rows ─────────────────────────
      const classified = rows.map(row => {
        const cached = cacheMap.get(String(row.id));
        // Only trust the cache if it's a firm verdict, or if it was successfully AI-verified
        if (cached && !(cached.type === 'POSSIBLE' && cached.ai_verified === 0)) {
          // Return cached verdict — zero Groq cost
          return {
            id:            row.id,
            gymId:         row.gym_id,
            nom:           row.nom,
            cleanedNom:    cleanName(row.nom),
            date:          row.date,
            abonnement:    row.abonnement,
            total:         row.total,
            type:          cached.type,
            confidence:    cached.confidence,
            matchedName:   cached.matched_name,
            prevClub:      cached.prev_club,
            prevGymId:     cached.prev_gym_id,
            prevStatus:    cached.prev_status,
            lastSub:       cached.last_sub,
            aiVerified:    cached.ai_verified === 1,
            aiReason:      cached.ai_reason,
            detectionMode: cached.detection_mode,
            usedVariant:   cached.used_variant,
            wasSplit:      cached.was_split === 1,
            topCandidates: [],
            fromCache:     true,
          };
        }

        const cleanedNom = cleanName(row.nom);
        const result     = findBestMatch(row.nom);
        
        let type          = 'NEW';
        let confidence    = result?.score || 0;
        let detectionMode = 'FUZZY';
        let aiReason      = null;

        // ── BIRTHDAY UPGRADE LOGIC ──
        // Do we know this new person's birthday from our local app members?
        const memberBday = localBirthdays.get(cleanedNom);
        let bdayMatched = false;

        if (memberBday && result?.topCandidates) {
          // Does any of the Odoo candidates share this EXACT birthday?
          const matchCand = result.topCandidates.find(c => c.x_birthday === memberBday);
          if (matchCand) {
            type          = 'RESUB';
            confidence    = 100;
            detectionMode = 'BIRTHDAY-MATCH';
            aiReason      = `Birthday verified (${memberBday})`;
            bdayMatched   = true;
            
            // Override the fuzzy matched member with this confirmed candidate
            result.match     = matchCand.full_name || matchCand.name;
            result.prevClub  = matchCand.club;
            result.prevGymId = matchCand.gymId;
            result.status    = matchCand.status;
            result.lastSub   = matchCand.subs_stop;
          }
        }

        // If no birthday match, fallback to standard fuzzy thresholds
        if (!bdayMatched) {
          if (confidence >= 85) type = 'RESUB';
          else if (confidence >= 70) type = 'POSSIBLE';
        }

        return {
          id:            row.id,
          gymId:         row.gym_id,
          nom:           row.nom,
          cleanedNom,
          date:          row.date,
          abonnement:    row.abonnement,
          total:         row.total,
          type,
          confidence,
          matchedName:   result?.match || null,
          prevClub:      result?.prevClub || null,
          prevGymId:     result?.prevGymId || null,
          prevStatus:    result?.status || null,
          lastSub:       result?.lastSub || null,
          topCandidates: result?.topCandidates || [],
          aiVerified:    bdayMatched,  // Count birthday match as "verified"
          aiReason,
          detectionMode,
          usedVariant:   result?.usedVariant || null,
          wasSplit:      result?.wasSplit || false,
          fromCache:     false,
        };
      });

      // ── PASS 2: Groq AI validates uncached POSSIBLE cases ────────────────
      const uncachedPossibles = classified.filter(c => c.type === 'POSSIBLE' && !c.fromCache);
      if (uncachedPossibles.length > 0) {
        try {
          const groqResults = await groqBatchValidate(uncachedPossibles);
          for (const member of classified) {
            if (member.fromCache) continue;
            const aiResult = groqResults.get(String(member.id));
            if (aiResult) {
              member.type          = aiResult.verdict === 'RESUB' ? 'RESUB' : 'NEW';
              member.confidence    = aiResult.confidence ?? member.confidence;
              member.aiVerified    = true;
              member.aiReason      = aiResult.reason || null;
              member.detectionMode = 'AI+FUZZY';
            }
          }
        } catch (groqErr) {
          console.warn('[ReSubAI] Groq batch skipped:', groqErr.message);
        }
      }

      // ── PASS 3: Persist ALL new verdicts to SQLite cache ─────────────────
      // Skip caching POSSIBLE cases if AI validation failed (e.g., rate limit hit).
      // This forces the system to re-try them on the next page refresh.
      const newlyClassified = classified.filter(c => !c.fromCache && !(c.type === 'POSSIBLE' && !c.aiVerified));
      if (newlyClassified.length > 0) {
        const insertCache = lc.db.prepare(`
          INSERT OR REPLACE INTO resub_intelligence_cache
            (register_id, gym_id, nom_key, type, confidence, matched_name,
             prev_club, prev_gym_id, prev_status, last_sub, ai_verified,
             ai_reason, detection_mode, used_variant, was_split, cached_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        const insertMany = lc.db.transaction(items => {
          for (const m of items) {
            insertCache.run(
              String(m.id), m.gymId, m.cleanedNom, m.type, m.confidence,
              m.matchedName, m.prevClub, m.prevGymId, m.prevStatus, m.lastSub,
              m.aiVerified ? 1 : 0, m.aiReason, m.detectionMode,
              m.usedVariant, m.wasSplit ? 1 : 0, NOW_ISO
            );
          }
        });
        insertMany(newlyClassified);
        console.log(`[ReSubCache] ✅ Saved ${newlyClassified.length} new verdicts to SQLite cache`);
      }


      // Per-gym aggregation
      const perGym = {};
      for (const g of gymIds) {
        const members = classified.filter(c => c.gymId === g);
        perGym[g] = {
          gymId:      g,
          clubName:   GYM_TO_CLUB[g] || g,
          total:      members.length,
          newCount:   members.filter(c => c.type === 'NEW').length,
          resubCount: members.filter(c => c.type === 'RESUB').length,
          possible:   members.filter(c => c.type === 'POSSIBLE').length,
          resubRate:  members.length > 0
            ? Math.round((members.filter(c => c.type !== 'NEW').length / members.length) * 100)
            : 0,
          members,
        };
      }

      // Summary across all selected gyms
      const totalNew   = classified.filter(c => c.type === 'NEW').length;
      const totalResub = classified.filter(c => c.type === 'RESUB').length;
      const totalPoss  = classified.filter(c => c.type === 'POSSIBLE').length;

      res.json({
        ok: true,
        month: dateLabel,
        dateRange: { startDate, endDate },
        gymIds,
        summary: { total: classified.length, newCount: totalNew, resubCount: totalResub, possible: totalPoss },
        perGym,
        members: classified,
        csvIndexSize: _csvCache?.members?.length || 0,
        cacheStats: {
          hits:   cacheMap.size,
          misses: classified.length - cacheMap.size,
          total:  classified.length,
        },
      });
    } catch (err) {
      console.error('GET /api/sales/resub-matrix error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // DELETE /api/sales/resub-cache/clear?gymId=all  — invalidate SQLite verdicts
  // Use when fuzzy thresholds change or CSV is updated
  // ─────────────────────────────────────────────────────────────────────────────
  router.delete('/resub-cache/clear', verifyAzureToken, (req, res) => {
    try {
      const { gymId } = req.query;
      if (gymId && gymId !== 'all') {
        const result = lc.db.prepare('DELETE FROM resub_intelligence_cache WHERE gym_id = ?').run(gymId);
        console.log(`[ReSubCache] Cleared ${result.changes} entries for gym: ${gymId}`);
        res.json({ ok: true, cleared: result.changes, gym: gymId });
      } else {
        const result = lc.db.prepare('DELETE FROM resub_intelligence_cache').run();
        console.log(`[ReSubCache] Cleared ALL ${result.changes} cached verdicts`);
        res.json({ ok: true, cleared: result.changes, gym: 'all' });
      }
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // POST /api/sales/resub-deep-scan
  // ★ SECOND AI PASS — targets NEW members with moderate fuzzy score (40-69%)
  //   that the first pass missed. AI gets broader Moroccan-context prompt.
  //   Results saved to SQLite cache (ai_verified=1, type upgraded if RESUB found).
  // ─────────────────────────────────────────────────────────────────────────────
  router.post('/resub-deep-scan', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'all', startMonth, endMonth, minScore = 40 } = req.body;

      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : (Array.isArray(gymId) ? gymId : gymId.split(',').map(s => s.trim()));

      const ph = gymIds.map(() => '?').join(',');

      // Targets: cached NEW members with moderate confidence that were NOT AI-verified
      // Score 40-69%: fuzzy said "probably new" but it's uncertain territory
      let query = `
        SELECT r.register_id, r.gym_id, r.nom_key, r.confidence, r.matched_name,
               r.used_variant, r.was_split
        FROM resub_intelligence_cache r
        WHERE r.gym_id IN (${ph})
          AND r.type = 'NEW'
          AND r.ai_verified = 0
          AND r.confidence >= ?
      `;
      const queryArgs = [...gymIds, minScore];

      // Apply date filter if provided
      if (startMonth && endMonth) {
        query = `
          SELECT r.register_id, r.gym_id, r.nom_key, r.confidence, r.matched_name,
                 r.used_variant, r.was_split,
                 rc.nom, rc.date
          FROM resub_intelligence_cache r
          JOIN register_cache rc ON rc.id = r.register_id
          WHERE r.gym_id IN (${ph})
            AND r.type = 'NEW'
            AND r.ai_verified = 0
            AND r.confidence >= ?
            AND rc.date >= ? AND rc.date <= ?
        `;
        queryArgs.push(`${startMonth}-01`, `${endMonth}-31`);
      }

      const targets = lc.db.prepare(query).all(...queryArgs);
      if (targets.length === 0) {
        return res.json({ ok: true, scanned: 0, upgraded: 0, message: 'No targets for deep scan' });
      }

      console.log(`[DeepScan] 🔍 Starting deep AI scan: ${targets.length} NEW members (score 40-69%)`);

      // Build enriched candidate list for each target using fuzzy
      loadOdooCSV();
      const enriched = targets.map(t => {
        const result = findBestMatch(t.nom_key);
        return {
          id:            t.register_id,
          cleanedNom:    t.nom_key,
          confidence:    t.confidence,
          topCandidates: result?.topCandidates || [],
        };
      });

      // Run Groq with a special DEEP SCAN prompt (broader, more permissive)
      // Override the batch validator temporarily with deep-scan mode
      const deepScanMap = await groqDeepScan(enriched);

      // Persist upgrades to cache
      const updateStmt = lc.db.prepare(`
        UPDATE resub_intelligence_cache
        SET type = ?, confidence = ?, ai_verified = 1, ai_reason = ?,
            detection_mode = 'DEEP-SCAN', cached_at = ?
        WHERE register_id = ?
      `);
      const applyUpgrades = lc.db.transaction(items => {
        for (const [id, verdict] of items) {
          updateStmt.run(
            verdict.verdict === 'RESUB' ? 'RESUB' : 'NEW',
            verdict.confidence,
            verdict.reason,
            new Date().toISOString(),
            String(id)
          );
        }
      });
      applyUpgrades([...deepScanMap.entries()]);

      const upgraded = [...deepScanMap.values()].filter(v => v.verdict === 'RESUB').length;
      console.log(`[DeepScan] ✅ Completed: ${upgraded} hidden RESUB found out of ${targets.length} scanned`);

      res.json({
        ok: true,
        scanned:  targets.length,
        upgraded,
        aiCalls:  Math.ceil(targets.length / 8),
        message: `Deep scan found ${upgraded} hidden re-subscriptions in ${targets.length} previously classified NEW members`,
      });
    } catch (err) {
      console.error('[DeepScan] Error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // POST /api/sales/resub-single-check — manual override for a specific row
  // ─────────────────────────────────────────────────────────────────────────────
  router.post('/resub-single-check', verifyAzureToken, async (req, res) => {
    try {
      const { id, nom } = req.body;
      if (!id || !nom) return res.status(400).json({ error: 'Missing id or nom' });

      // Run fresh fuzzy search to get top candidates
      const result = findBestMatch(nom);
      
      const payload = {
        id,
        cleanedNom: cleanName(nom),
        topCandidates: result?.topCandidates || []
      };

      // Call Groq specifically for this one person
      const groqResults = await groqBatchValidate([payload]);
      const aiResult = groqResults.get(String(id));

      if (!aiResult) {
        return res.status(500).json({ error: 'L\'IA a échoué (Rate Limit). Réessayez dans 60s.' });
      }

      // ── CACHE UPDATE ──
      lc.db.prepare(`
        UPDATE resub_intelligence_cache
        SET type = ?, confidence = ?, ai_verified = 1, ai_reason = ?, detection_mode = 'AURALIX'
        WHERE register_id = ?
      `).run(
        aiResult.verdict === 'RESUB' ? 'RESUB' : (aiResult.verdict === 'POSSIBLE' ? 'POSSIBLE' : 'NEW'),
        aiResult.confidence || result.score,
        aiResult.reason || null,
        String(id)
      );

      res.json({
        ok: true,
        type: aiResult.verdict === 'RESUB' ? 'RESUB' : (aiResult.verdict === 'POSSIBLE' ? 'POSSIBLE' : 'NEW'),
        confidence: aiResult.confidence || result.score,
        aiReason: aiResult.reason || null
      });

    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // POST /api/sales/resub-force-new — manually mark as not a match
  // ─────────────────────────────────────────────────────────────────────────────
  router.post('/resub-force-new', verifyAzureToken, async (req, res) => {
    try {
      const { id } = req.body;
      if (!id) return res.status(400).json({ error: 'Missing id' });

      lc.db.prepare(`
        UPDATE resub_intelligence_cache
        SET type = 'NEW', confidence = 0, ai_verified = 1, ai_reason = 'Correction manuelle: Pas de match', 
            matched_name = NULL, prev_club = NULL, detection_mode = 'AURALIX'
        WHERE register_id = ?
      `).run(String(id));

      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/sales/resub-candidates?name=... — get fuzzy match suggestions
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/resub-candidates', verifyAzureToken, (req, res) => {
    try {
      const name = req.query.name;
      if (!name) return res.status(400).json({ error: 'Missing name' });

      const result = findBestMatch(name);
      const candidates = (result?.topCandidates || []).map(c => ({
        name: c.full_name,
        club: c.club,
        status: c.status,
        subs_stop: c.subs_stop,
        score: c.score
      }));

      res.json(candidates);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });


  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/sales/odoo-search?q=... — search the 12k Odoo CSV list
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/odoo-search', verifyAzureToken, (req, res) => {
    try {
      const q = (req.query.q || '').trim().toUpperCase();
      if (!q || q.length < 3) return res.json([]);

      const { members } = loadOdooCSV();
      const results = members
        .filter(m => m.full_name.includes(q))
        .slice(0, 15)
        .map(m => ({
          name: m.full_name,
          club: m.club,
          status: m.status,
          subs_stop: m.subs_stop,
          x_birthday: m.x_birthday
        }));

      res.json(results);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // POST /api/sales/resub-manual-assign — manually link an inscription to an Odoo member
  // ─────────────────────────────────────────────────────────────────────────────
  router.post('/resub-manual-assign', verifyAzureToken, async (req, res) => {
    try {
      const { id, matchedMember } = req.body;
      if (!id || !matchedMember) return res.status(400).json({ error: 'Missing data' });

      lc.db.prepare(`
        UPDATE resub_intelligence_cache
        SET type = 'RESUB', confidence = 100, ai_verified = 1, 
            ai_reason = 'Assignation manuelle', 
            matched_name = ?, prev_club = ?, prev_status = ?, last_sub = ?, detection_mode = 'AURALIX'
        WHERE register_id = ?
      `).run(
        matchedMember.name,
        matchedMember.club,
        matchedMember.status,
        matchedMember.subs_stop,
        String(id)
      );

      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/sales/resub-cache/stats — how many inscriptions are cached
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/resub-cache/stats', verifyAzureToken, (req, res) => {
    try {
      const total    = lc.db.prepare('SELECT COUNT(*) AS n FROM resub_intelligence_cache').get().n;
      const aiVerif  = lc.db.prepare("SELECT COUNT(*) AS n FROM resub_intelligence_cache WHERE ai_verified = 1").get().n;
      const deepScan = lc.db.prepare("SELECT COUNT(*) AS n FROM resub_intelligence_cache WHERE detection_mode = 'DEEP-SCAN'").get().n;
      const resubs   = lc.db.prepare("SELECT COUNT(*) AS n FROM resub_intelligence_cache WHERE type = 'RESUB'").get().n;
      const news     = lc.db.prepare("SELECT COUNT(*) AS n FROM resub_intelligence_cache WHERE type = 'NEW'").get().n;
      const pending  = lc.db.prepare("SELECT COUNT(*) AS n FROM resub_intelligence_cache WHERE type = 'POSSIBLE'").get().n;
      res.json({ ok: true, total, aiVerified: aiVerif, deepScanned: deepScan, resubs, news, pending });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/commercials — list registered commercial names (legacy)
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat' } = req.query;
      const snap = await db.collection('gym_commercials').where('gymId', '==', gymId).get();
      const commercials = snap.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      res.json({ ok: true, commercials });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch commercials' });
    }
  });

  return router;

};

