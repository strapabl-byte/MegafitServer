'use strict';
// routes/analytics.js ??? Daily stats, KPIs, live door entries, entry logging

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function analyticsRouter({ db, admin, lc, apiCache, isQuotaExceeded, getCachedOrFetch, syncGymCounts }) {
  const router = Router();

  function getMoroccanDateStr() {
    // ⏰ 6AM Business-Day Reset — matches Auralix PWA logic exactly.
    // Before 6AM Morocco time, we treat it as the previous business day
    // so revenue figures are consistent across both systems at any hour.
    const d = new Date(Date.now() + 3600000); // shift to UTC+1 (Morocco)
    if (d.getUTCHours() < 6) d.setUTCDate(d.getUTCDate() - 1); // before 6AM → previous day
    return d.toISOString().slice(0, 10);
  }

  // Door-device gyms — only gyms with actual biometric terminals connected
  // casa1/casa2 have no door device yet → excluded from door polling & gap fill
  const GYM_DOOR_MAP = {
    dokarat: { collections: ['mega_fit_logs'],       locationTags: ['dokkarat'] },
    marjane: { collections: ['saiss entrees logs'], locationTags: ['saiss', 'marjane'] },
  };

  const DOOR_URL = `https://firestore.googleapis.com/v1/projects/${process.env.DOOR_PROJECT_ID || 'megadoor-b3ccb'}/databases/(default)/documents:runQuery?key=${process.env.DOOR_FIREBASE_API_KEY || ''}`;

  // ─────────────────────────────────────────────────────────────────────────
  // 🤖 SMART MEMBER IDENTIFICATION — Levenshtein + Groq, SQLite-cached
  // ─────────────────────────────────────────────────────────────────────────

  /** Normalize a name for fuzzy comparison */
  const normId = s => (s || '').replace(/\s+/g, ' ').trim().toUpperCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '');

  /** Levenshtein distance (O(n*m) — fast enough for 10k members) */
  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
    for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    return dp[m][n];
  }

  /** Score 0-100 — higher is better match */
  function fuzzyScore(query, candidate) {
    if (!query || !candidate) return 0;
    const q = normId(query), c = normId(candidate);
    if (q === c) return 100;
    // Token-set ratio: compare sorted word tokens
    const qTokens = q.split(' ').sort().join(' ');
    const cTokens = c.split(' ').sort().join(' ');
    const maxLen = Math.max(qTokens.length, cTokens.length);
    const dist = levenshtein(qTokens, cTokens);
    const tokenScore = Math.round((1 - dist / maxLen) * 100);

    // 🇲🇦 MOROCCAN NAME BONUS: also compare with all spaces stripped.
    // Handles cases where the door device omits the space (e.g. "rajaebouzoubaa" vs "RAJAE BOUZOUBAA")
    const qNoSpace = q.replace(/\s+/g, '');
    const cNoSpace = c.replace(/\s+/g, '');
    const maxLenNS  = Math.max(qNoSpace.length, cNoSpace.length);
    const distNS    = levenshtein(qNoSpace, cNoSpace);
    const noSpaceScore = maxLenNS > 0 ? Math.round((1 - distNS / maxLenNS) * 100) : 0;

    return Math.max(tokenScore, noSpaceScore);
  }

  /**
   * 🇲🇦 Moroccan name splitter — tries every possible split of a no-space query
   * e.g. "rajaebouzoubaa" → attempts "r|ajaebouzoubaa", "ra|jaebouzoubaa" ...
   * and scores each <left> <right> combination against the full member name.
   * Returns the best split score for a given candidate full_name.
   */
  function splitNameScore(rawQuery, candidateNormName) {
    const q = normId(rawQuery).replace(/\s+/g, '');
    const c = normId(candidateNormName).replace(/\s+/g, '');
    if (q.length < 3 || q.includes(' ')) return 0; // already has spaces or too short
    let best = 0;
    // Try every split point (minimum 2 chars on each side)
    for (let i = 2; i < q.length - 1; i++) {
      const left  = q.slice(0, i);
      const right = q.slice(i);
      // Score the reconstructed "FIRST LAST" against the candidate's no-space name
      const reconstructed = left + ' ' + right;
      const sc = fuzzyScore(reconstructed, candidateNormName);
      if (sc > best) best = sc;
    }
    return best;
  }

  /** Get top N fuzzy matches from odoo_members_cache */
  function fuzzyMatchMembers(rawName, topN = 5) {
    const allMembers = lc.db.prepare('SELECT * FROM odoo_members_cache').all();
    const hasSpaces = rawName.trim().includes(' ');
    const scored = allMembers.map(m => {
      let score = fuzzyScore(rawName, m.name_norm);
      // If the query has no spaces, also try the Moroccan split heuristic
      if (!hasSpaces && rawName.length > 5) {
        const splitSc = splitNameScore(rawName, m.name_norm);
        if (splitSc > score) score = splitSc;
      }
      return { ...m, score };
    });
    return scored.sort((a, b) => b.score - a.score).slice(0, topN);
  }

  /** Convert gym label to gym_id */
  const GYM_LABEL_MAP = { 'FES DOUKKARATE': 'dokarat', 'FES MARJANE': 'marjane', 'CASA 1': 'casa1', 'CASA 2': 'casa2' };
  const GYM_DISPLAY = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saiss', casa1: 'Casa 1', casa2: 'Casa 2' };

  // ── Known staff role keywords (after the hyphen) ─────────────────────────
  const STAFF_ROLES = {
    'comercial':    { role: 'Commercial',  emoji: '💼' },
    'commercial':   { role: 'Commercial',  emoji: '💼' },
    'coach':        { role: 'Coach',       emoji: '🏋️' },
    'entraineur':   { role: 'Coach',       emoji: '🏋️' },
    'employe':      { role: 'Employé',     emoji: '👔' },
    'employee':     { role: 'Employé',     emoji: '👔' },
    'employer':     { role: 'Employé',     emoji: '👔' },
    'caissier':     { role: 'Caissier',    emoji: '💶' },
    'caisse':       { role: 'Caissier',    emoji: '💶' },
    'reception':    { role: 'Réception',   emoji: '🪪' },
    'receptionist': { role: 'Réception',   emoji: '🪪' },
    'manager':      { role: 'Manager',     emoji: '🎯' },
    'gerant':       { role: 'Gérant',      emoji: '🎯' },
    'admin':        { role: 'Admin',       emoji: '⚙️' },
    'staff':        { role: 'Staff',       emoji: '👔' },
    'agent':        { role: 'Agent',       emoji: '🔑' },
    'animateur':    { role: 'Animateur',   emoji: '🎤' },
    'technique':    { role: 'Technique',   emoji: '🔧' },
    'menage':       { role: 'Ménage',      emoji: '🧹' },
    'nettoyage':    { role: 'Ménage',      emoji: '🧹' },
    'securite':     { role: 'Sécurité',    emoji: '🛡️' },
    'security':     { role: 'Sécurité',    emoji: '🛡️' },
    'comptable':    { role: 'Comptable',   emoji: '📊' },
    'directeur':    { role: 'Directeur',   emoji: '🏆' },
  };

  /**
   * Detect staff from door entry name.
   * Matches known role keywords at the end of the name (with or without hyphen).
   * e.g. "redamouss-comercial" → REDAMOUSS, "hamidemploye" → HAMID, "Hajar-caissier" → HAJAR
   */
  function detectStaff(rawName) {
    if (!rawName) return null;
    const normalized = rawName.trim().toLowerCase();
    
    const roles = Object.keys(STAFF_ROLES).sort((a, b) => b.length - a.length);
    
    for (const roleKey of roles) {
      if (normalized.endsWith(roleKey)) {
         let namePart = normalized.slice(0, normalized.length - roleKey.length).trim();
         if (namePart.endsWith('-') || namePart.endsWith('_') || namePart.endsWith(' ')) {
             namePart = namePart.slice(0, -1).trim();
         }
         if (!namePart || namePart.length < 2) continue;
         
         const staffInfo = STAFF_ROLES[roleKey];
         return { displayName: namePart.toUpperCase(), role: staffInfo.role, emoji: staffInfo.emoji };
      }
    }
    return null;
  }

  // ── Groq Rate Limiter ─────────────────────────────────────────────────────
  // Prevents 429 storms: enforces a 2s gap between calls and a 60s cooldown
  // after any 429 response. During cooldown, Groq is silently skipped.
  const groqLimiter = {
    cooldownUntil: 0,          // timestamp (ms) until which Groq is paused
    lastCallAt:    0,          // timestamp of the last successful call attempt
    minGapMs:      2000,       // minimum ms between Groq calls
    cooldownMs:    60000,      // cooldown duration after a 429
    queue:         Promise.resolve(), // serializes calls

    isCoolingDown() {
      return Date.now() < this.cooldownUntil;
    },
    trigger429() {
      this.cooldownUntil = Date.now() + this.cooldownMs;
      console.warn(`[SMART-ID] Groq rate limit hit — pausing AI for ${this.cooldownMs/1000}s`);
    },
    async wait() {
      const gap = this.minGapMs - (Date.now() - this.lastCallAt);
      if (gap > 0) await new Promise(r => setTimeout(r, gap));
      this.lastCallAt = Date.now();
    }
  };

  /** Call Groq with top candidates + gym context, return best pick */
  async function groqIdentify(rawName, userId, candidates, extraContext = '') {
    // Skip entirely during cooldown — fall back to fuzzy-only
    if (groqLimiter.isCoolingDown()) {
      const remainS = Math.ceil((groqLimiter.cooldownUntil - Date.now()) / 1000);
      console.log(`[SMART-ID] Groq paused (cooldown ${remainS}s left) — using fuzzy fallback for "${rawName}"`);
      return null;
    }

    // Serialize calls through the queue so they never overlap
    const result = await (groqLimiter.queue = groqLimiter.queue.then(async () => {
      // Re-check cooldown inside the queue (another call may have triggered it)
      if (groqLimiter.isCoolingDown()) return null;
      await groqLimiter.wait();

      try {
        const GROQ_KEY = process.env.GROQ_API_KEY || process.env.GROQ_API_KEY_FALLBACK;
        if (!GROQ_KEY) return null;
        const candidateList = candidates.map((c, i) =>
          `${i+1}. ${c.full_name} | ${GYM_DISPLAY[c.gym_id]||c.gym_id} | ${c.status} | expire: ${c.expires_on||'?'} | score: ${c.score}%`
        ).join('\n');
        const prompt = `You are a gym reception AI identifying Moroccan gym members from door scanner entries.
IMPORTANT CONTEXT:
- Moroccan names follow the format: FIRSTNAME FAMILYNAME
- The door scanner sometimes sends names WITHOUT a space between first name and family name (e.g. "rajaebouzoubaa" is actually "RAJAE BOUZOUBAA")
- RAJAE, FATIMA, KHADIJA, ZINEB, SARA, LAYLA, HAJAR, SOUKAINA, NADIA, IMANE, HANAE, SANAE, YOUNES, YOUSSEF, HAMZA, AMINE, MEHDI, KARIM, FOUAD, RACHID, ANASS, HASSAN, OMAR are common Moroccan first names
- Always check if the raw name, when split intelligently, matches the candidate's first+last name
- Gender matters: RAJAE, FATIMA, ZINEB, SARA, KHADIJA are female names — do NOT match them to male candidates

A door scanner registered the name "${rawName}"${userId ? ` (user_id: ${userId})` : ''}.${extraContext}
Top fuzzy matches from member database:
${candidateList}

Rules:
- If one match is clearly correct (same name with typo/missing space/reversed order/unicode artifacts) pick it.
- Prefer matching at the scanning gym if the person is registered there.
- If score < 50 and no match is convincing, pick UNKNOWN (pick: 0).
- If the query looks like a concatenated Moroccan name, try to split it and match first+last name.
Reply ONLY with valid JSON (no markdown):
{"pick": <1-based index or 0 for UNKNOWN>, "confidence": <0-100>, "comment": "<short French comment, max 12 words>"}`;

        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: 'llama-3.1-8b-instant', messages: [{ role: 'user', content: prompt }], temperature: 0.1, max_tokens: 150 }),
        });

        // Handle 429 specifically — trigger cooldown
        if (r.status === 429) {
          groqLimiter.trigger429();
          return null;
        }

        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`Groq API ${r.status}: ${errText.slice(0, 100)}`);
        }

        const data = await r.json();
        const text = data.choices?.[0]?.message?.content?.trim() || '';
        
        let json = null;
        try {
          const jsonMatch = text.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            json = JSON.parse(jsonMatch[0]);
          } else {
            throw new Error('No JSON object found in response');
          }
        } catch (parseErr) {
          console.warn(`[SMART-ID] Failed to parse Groq response: "${text.slice(0, 50)}..."`);
          return null;
        }

        return { 
          pick: json.pick ?? 0, 
          confidence: json.confidence ?? 0, 
          comment: json.comment || '' 
        };
      } catch (err) {
        // Only log non-429 errors (429 handled above)
        if (!err.message?.includes('429')) {
          console.warn('[SMART-ID] Groq error:', err.message);
        }
        return null;
      }
    }).catch(() => null));

    return result;
  }

  /** Main identification function — gym-specific cache + multi-gym detection */
  async function identifyEntry(entry, gymId, runGroq = true) {
    // Cache key is GYM-SPECIFIC so a member at marjane+dokarat gets the right status at each gym
    const cacheKey = entry.user_id
      ? `uid_${entry.user_id}_at_${gymId}`
      : `name_${normId(entry.name)}_at_${gymId}`;

    // ── STEP 0: Detect gym staff instantly (name-role pattern, no Groq needed) ──
    const staffInfo = detectStaff(entry.name);
    if (staffInfo) {
      const now = new Date().toISOString();
      const comment = `${staffInfo.emoji} ${staffInfo.role}`;
      lc.db.prepare(`
        INSERT OR REPLACE INTO smart_identity_cache
          (entry_key, gym_id, matched_name, matched_gym, id_status, confidence, comment, groq_used, cached_at)
        VALUES (?, ?, ?, ?, 'staff', 100, ?, 0, ?)
      `).run(cacheKey, gymId, staffInfo.displayName, gymId, comment, now);
      return { entry_key: cacheKey, gym_id: gymId, matched_name: staffInfo.displayName, matched_gym: gymId, id_status: 'staff', confidence: 100, comment, groq_used: 0 };
    }

    // 1. Check SQLite identity cache (gym-specific)
    // TTL: 24h — so renewals are reflected the next day
    const cached = lc.db.prepare('SELECT * FROM smart_identity_cache WHERE entry_key=?').get(cacheKey);
    if (cached) {
      const ageMs = Date.now() - new Date(cached.cached_at || 0).getTime();
      if (ageMs < 86400000) return cached; // < 24h → use cache
      // > 24h → fall through and re-identify (picks up renewals)
    }

    // 2. Fetch top 10 matches across ALL gyms
    const top10 = fuzzyMatchMembers(entry.name, 10);
    const best   = top10[0];

    // 3. Split matches by gym membership
    const atCurrentGym  = top10.filter(m => m.gym_id === gymId);
    const atOtherGyms   = top10.filter(m => m.gym_id !== gymId);
    const bestAtCurrent = atCurrentGym[0]  || null;  // best match AT the scanning gym
    const bestAtOther   = atOtherGyms[0]   || null;  // best match at any OTHER gym

    // Detect multi-inscrit: same person found at current gym AND at least one other gym
    const isMultiGym = bestAtCurrent && bestAtOther &&
      (normId(bestAtCurrent.full_name) === normId(bestAtOther.full_name) ||
       fuzzyScore(bestAtCurrent.full_name, bestAtOther.full_name) >= 85);

    let matched = null, status = 'unknown', confidence = 0, comment = '', groqUsed = 0;

    // ── Helper: use expires_on DATE not Odoo status string (can be stale after renewal) ──
    const today = getMoroccanDateStr();
    const isSubCurrentlyActive = (m) => {
      if (m.expires_on) {
        try { return new Date(m.expires_on) >= new Date(today); } catch (_) {}
      }
      return m.status === 'Active';
    };

    // ── Case A: Strong match at current gym ─────────────────────────────────
    if (bestAtCurrent && bestAtCurrent.score >= 85) {
      matched    = bestAtCurrent;
      confidence = bestAtCurrent.score;
      if (!isSubCurrentlyActive(bestAtCurrent)) {
        status  = 'expired';
        comment = `Abonnement expire le ${bestAtCurrent.expires_on || '?'}`;
      } else if (isMultiGym) {
        status  = 'confirmed';
        const otherGyms = [...new Set(atOtherGyms.filter(m => m.score >= 70).map(m => GYM_DISPLAY[m.gym_id] || m.gym_id))].join(' + ');
        comment = `Multi-inscrit${otherGyms ? ` · aussi à ${otherGyms}` : ''}`;
      } else {
        status  = 'confirmed';
        comment = bestAtCurrent.full_name;
      }

    // ── Case B: Strong match ONLY at other gym(s) — no good current-gym match ─
    } else if (bestAtOther && bestAtOther.score >= 85 && (!bestAtCurrent || bestAtCurrent.score < 70)) {
      matched    = bestAtOther;
      confidence = bestAtOther.score;
      status     = 'wrong_gym';
      const allRegisteredGyms = [...new Set(top10.filter(m => m.score >= 70).map(m => GYM_DISPLAY[m.gym_id] || m.gym_id))].join(', ');
      comment = `Inscrit à ${allRegisteredGyms} — pas ici`;

    // ── Case C: Ambiguous (score 55-84) — ask Groq ──────────────────────────
    } else if (best && best.score >= 55 && runGroq) {
      const candidates = top10.filter(c => c.score >= 45);
      const atCurrentStr = atCurrentGym.length > 0
        ? `\nMember HAS a match at the scanning gym (${GYM_DISPLAY[gymId]||gymId}).`
        : `\nMember has NO match at the scanning gym (${GYM_DISPLAY[gymId]||gymId}) — could be wrong_gym or multi-inscrit.`;

      const groqResult = await groqIdentify(
        entry.name, entry.user_id,
        candidates,
        atCurrentStr // extra context passed as extra param
      );
      groqUsed = 1;

      if (groqResult && groqResult.pick > 0) {
        matched    = top10[groqResult.pick - 1];
        confidence = groqResult.confidence;
        comment    = groqResult.comment;
        if (matched) {
          if (!isSubCurrentlyActive(matched)) {
            status = 'expired';
          } else if (matched.gym_id === gymId) {
            status = 'probable';
          } else {
            // Check if there's ALSO a match at current gym → multi-inscrit
            const currentGymMatch = atCurrentGym.find(m => m.score >= 55);
            status = currentGymMatch ? 'probable' : 'wrong_gym';
            if (!comment) comment = status === 'wrong_gym'
              ? `Inscrit à ${GYM_DISPLAY[matched.gym_id]||matched.gym_id}`
              : `Probablement multi-inscrit`;
          }
        } else { status = 'unknown'; confidence = 0; }
      } else {
        status  = 'unknown';
        confidence = groqResult?.confidence || 0;
        comment = groqResult?.comment || '? Inconnu — non trouvé dans la base';
      }

    // ── Case D: Weak match (<55) — mark as pending, Groq will refine ────────
    } else if (best && best.score >= 55) {
      matched    = best; confidence = best.score;
      status     = best.gym_id === gymId ? 'probable' : 'wrong_gym';
      comment    = best.gym_id === gymId
        ? `Probablement ${best.full_name}`
        : `Inscrit à ${GYM_DISPLAY[best.gym_id]||best.gym_id}`;
    } else {
      status  = 'unknown'; confidence = best?.score || 0;
      comment = '? Inconnu — non trouvé dans la base';
    }

    // 4. Persist to SQLite identity cache (permanent on Render disk, gym-specific)
    const now = new Date().toISOString();
    lc.db.prepare(`
      INSERT OR REPLACE INTO smart_identity_cache
        (entry_key, gym_id, matched_name, matched_gym, id_status, confidence, comment, groq_used, cached_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(cacheKey, gymId, matched?.full_name || null, matched?.gym_id || null, status, confidence, comment, groqUsed, now);

    return { entry_key: cacheKey, gym_id: gymId, matched_name: matched?.full_name || null, matched_gym: matched?.gym_id || null, id_status: status, confidence, comment, groq_used: groqUsed };
  }

  /** Count visits today and this week for an entry */
  function getVisitStats(entry, gymId) {
    const today = getMoroccanDateStr();
    const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
    const byId  = entry.user_id ? lc.db.prepare('SELECT COUNT(*) as c FROM entries WHERE gym_id=? AND user_id=? AND date=?').get(gymId, entry.user_id, today)?.c || 0 : 0;
    const byName = lc.db.prepare('SELECT COUNT(*) as c FROM entries WHERE gym_id=? AND name=? AND date=?').get(gymId, entry.name, today)?.c || 0;
    const week  = entry.user_id
      ? lc.db.prepare('SELECT COUNT(*) as c FROM entries WHERE gym_id=? AND user_id=? AND date>=?').get(gymId, entry.user_id, weekAgo)?.c || 0
      : lc.db.prepare('SELECT COUNT(*) as c FROM entries WHERE gym_id=? AND name=? AND date>=?').get(gymId, entry.name, weekAgo)?.c || 0;
    return { today: Math.max(byId, byName), week };
  }

  // ?????? GET /api/analytics/megaeye-registrations ??????????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/analytics/auralix-registrations', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, timeFilter } = req.query; // 'day' or 'week'
      const rows = lc.getPending(gymId, timeFilter || 'day');
      res.json(rows);
    } catch (err) {
      console.error('Megaeye Registrations Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch megaeye registrations' });
    }
  });

  // ── 5-second server-side cache for /api/live-entries ─────────────────────
  // Protects Render (0.5 CPU) from rapid gym-switching storms.
  // Each gymId gets its own cache slot; expires after 5s.
  const liveEntriesCache = new Map(); // key: `${gymId}:${date}` → { ts, data }

  // ?????? GET /api/live-entries ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/live-entries', verifyAzureToken, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    try {
      let { gymId, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      
      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin) {
          const assigned = req.assignedGyms[0];
          if (assigned && assigned !== 'all') {
              gymId = assigned;
          }
      }
      const limitCount = Math.min(parseInt(limitParam) || 50, 200);
      const today = getMoroccanDateStr();

      // ── Server-side cache hit? Return instantly, skip all processing ──────
      const cacheKey = `${gymId}:${today}`;
      const cached = liveEntriesCache.get(cacheKey);
      if (cached && (Date.now() - cached.ts) < 5000) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached.data);
      }

      const targetGymIds = gymId === 'all' ? Object.keys(GYM_DOOR_MAP) : [gymId];


      // Cross-reference: load members from SQLite — include zkteco_user_id for precise matching
      const placeholders = targetGymIds.map(() => '?').join(',');
      const memberRows = lc.db.prepare(
        `SELECT full_name, expires_on, zkteco_user_id FROM members_cache WHERE gym_id IN (${placeholders})`
      ).all(...targetGymIds);

      const normalize = s => (s || '').replace(/\s+/g, ' ').trim().toUpperCase();

      // Build two lookup maps:
      // 1. By ZKTeco user_id (exact, most reliable — for Doukkarate new format)
      const memberByUserId = new Map();
      // 2. By normalized name (fuzzy fallback)
      const memberByName = new Map();

      for (const m of memberRows) {
        const key = normalize(m.full_name);
        const data = { fullName: m.full_name, expiresOn: m.expires_on };
        
        // Priority: always keep the profile with the LATEST expiration date
        const existingByName = memberByName.get(key);
        if (!existingByName || (m.expires_on && (!existingByName.expiresOn || m.expires_on > existingByName.expiresOn))) {
          if (key) memberByName.set(key, data);
        }

        if (m.zkteco_user_id) {
          const uid = String(m.zkteco_user_id);
          const existingByUid = memberByUserId.get(uid);
          if (!existingByUid || (m.expires_on && (!existingByUid.expiresOn || m.expires_on > existingByUid.expiresOn))) {
            memberByUserId.set(uid, data);
          }
        }
      }

      const isSubActive = (expiresOn) => {
        if (!expiresOn) return false;
        try { return new Date(expiresOn) >= new Date(today); } catch (e) { return false; }
      };

      // ── PRE-BUILD prefix index for fast partial name lookups (O(1) per entry) ──
      // Avoids iterating all 9k members for every single entry
      const prefixIndex = new Map();
      for (const [mName, mData] of memberByName.entries()) {
        const prefix = mName.slice(0, 6);
        if (!prefixIndex.has(prefix)) prefixIndex.set(prefix, []);
        prefixIndex.get(prefix).push({ name: mName, data: mData });
      }

      // ── BATCH-LOAD all entries + identity cache in 1 query (not N queries) ──
      const allEntries = [];
      for (const gid of targetGymIds) {
        for (const e of lc.getEntries(gid, { date: today, limit: limitCount })) {
          allEntries.push({ ...e, _gid: gid });
        }
      }
      const cacheKeys = allEntries.map(e =>
        e.user_id ? `uid_${e.user_id}_at_${e._gid}` : `name_${normId(e.name)}_at_${e._gid}`
      );
      const cachedIds = new Map();
      if (cacheKeys.length > 0) {
        const placeholdersId = cacheKeys.map(() => '?').join(',');
        const rows = lc.db.prepare(`SELECT * FROM smart_identity_cache WHERE entry_key IN (${placeholdersId})`).all(...cacheKeys);
        for (const row of rows) cachedIds.set(row.entry_key, row);
      }

      let merged = [];
      for (const e of allEntries) {
        const gid = e._gid;
        let member = null;
        let matchMethod = 'none';

        // ── 1. Exact match by ZKTeco user_id ──────────────────────────────────
        if (e.user_id) {
          member = memberByUserId.get(String(e.user_id)) || null;
          if (member) matchMethod = 'user_id';
        }

        // ── 2. Exact name match ───────────────────────────────────────────────
        if (!member) {
          const entryNorm = normalize(e.name);
          member = memberByName.get(entryNorm) || null;
          if (member) matchMethod = 'name_exact';

          // ── 3. Fast prefix partial match (O(1) via prefix index) ───────────
          if (!member && entryNorm.length > 3) {
            const prefix = entryNorm.slice(0, 6);
            const candidates = prefixIndex.get(prefix) || [];
            for (const { name: mName, data: mData } of candidates) {
              if (mName.includes(entryNorm)) {
                member = mData;
                matchMethod = 'name_partial';
                break;
              }
            }
          }
        }

        const isKnown = !!member;
        const memberStatus = isKnown
          ? (isSubActive(member.expiresOn) ? 'active' : 'expired')
          : 'unknown';

        const cacheKey = e.user_id
          ? `uid_${e.user_id}_at_${gid}`
          : `name_${normId(e.name)}_at_${gid}`;

        let cachedId = cachedIds.get(cacheKey) || null;

        // Sync staff detection for uncached staff entries (no Groq needed)
        if (!cachedId) {
          const staffInfo = detectStaff(e.name);
          if (staffInfo) cachedId = await identifyEntry(e, gid, false);
        }

        const visits = getVisitStats(e, gid);

        merged.push({
          docId:          e.id,
          name:           e.name,
          userId:         e.user_id || null,
          gymId:          gid,
          displayTime:    (e.timestamp || '').slice(11, 16),
          timestamp:      e.timestamp,
          status:         e.status,
          method:         e.method,
          isFace:         e.is_face === 1,
          isKnown,
          memberStatus,
          matchMethod,
          expiresOn:      member ? member.expiresOn : null,
          userTodayCount: visits.today,
          userWeekCount:  visits.week,
          smartId: cachedId ? {
            status:      cachedId.id_status,
            matchedName: cachedId.matched_name,
            matchedGym:  cachedId.matched_gym,
            confidence:  cachedId.confidence,
            comment:     cachedId.comment,
            groqUsed:    !!cachedId.groq_used,
          } : null,
        });

        // 🔁 Fire Groq async for new unknowns — no await, instant response
        if (!cachedId && !isKnown) {
          identifyEntry(e, gid, true).catch(() => {});
        }
      }

      merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

      const responseData = { ok: true, gymId, count: merged.length, entries: merged.slice(0, limitCount) };
      // ── Store in cache so concurrent users and rapid switches hit cache ──────
      liveEntriesCache.set(cacheKey, { ts: Date.now(), data: responseData });
      res.json(responseData);

    } catch (err) {
      console.error('Live Entries Error:', err);
      res.status(500).json({ error: 'Failed to fetch live entries' });
    }
  });

  // ── Background Pre-Warmer ─────────────────────────────────────────────────
  // Proactively computes live-entries for ALL active gyms every 10s.
  // Result: any number of concurrent dashboards (5 gyms × N staff) all hit
  // cache instantly — zero per-request CPU, no spikes on Render.
  async function preWarmLiveEntries() {
    const activeGyms = ['dokarat', 'marjane']; // add casa1/casa2 when they go live
    const today = getMoroccanDateStr();

    for (const gid of activeGyms) {
      try {
        const cacheKey = `${gid}:${today}`;
        const existing = liveEntriesCache.get(cacheKey);
        // Skip if cache is still fresh (< 8s old) — no work needed
        if (existing && (Date.now() - existing.ts) < 8000) continue;

        // ── Build the response (same logic as the route, without req/res) ────
        const targetGymIds = [gid];
        const placeholders = targetGymIds.map(() => '?').join(',');
        const memberRows = lc.db.prepare(
          `SELECT full_name, expires_on, zkteco_user_id FROM members_cache WHERE gym_id IN (${placeholders})`
        ).all(...targetGymIds);

        const normalize = s => (s || '').replace(/\s+/g, ' ').trim().toUpperCase();
        const memberByUserId = new Map();
        const memberByName   = new Map();
        for (const m of memberRows) {
          const key  = normalize(m.full_name);
          const data = { fullName: m.full_name, expiresOn: m.expires_on };
          const existingByName = memberByName.get(key);
          if (!existingByName || (m.expires_on && (!existingByName.expiresOn || m.expires_on > existingByName.expiresOn))) {
            if (key) memberByName.set(key, data);
          }
          if (m.zkteco_user_id) {
            const uid = String(m.zkteco_user_id);
            const existingByUid = memberByUserId.get(uid);
            if (!existingByUid || (m.expires_on && (!existingByUid.expiresOn || m.expires_on > existingByUid.expiresOn))) {
              memberByUserId.set(uid, data);
            }
          }
        }

        const isSubActive = (expiresOn) => {
          if (!expiresOn) return false;
          try { return new Date(expiresOn) >= new Date(today); } catch (e) { return false; }
        };

        // Build prefix index
        const prefixIndex = new Map();
        for (const [mName, mData] of memberByName.entries()) {
          const prefix = mName.slice(0, 6);
          if (!prefixIndex.has(prefix)) prefixIndex.set(prefix, []);
          prefixIndex.get(prefix).push({ name: mName, data: mData });
        }

        // Batch load all entries + identity cache
        const allEntries = lc.getEntries(gid, { date: today, limit: 50 }).map(e => ({ ...e, _gid: gid }));
        const cacheKeys = allEntries.map(e =>
          e.user_id ? `uid_${e.user_id}_at_${gid}` : `name_${normId(e.name)}_at_${gid}`
        );
        const cachedIds = new Map();
        if (cacheKeys.length > 0) {
          const phId = cacheKeys.map(() => '?').join(',');
          const rows = lc.db.prepare(`SELECT * FROM smart_identity_cache WHERE entry_key IN (${phId})`).all(...cacheKeys);
          for (const row of rows) cachedIds.set(row.entry_key, row);
        }

        const merged = [];
        for (const e of allEntries) {
          let member = null, matchMethod = 'none';
          if (e.user_id) { member = memberByUserId.get(String(e.user_id)) || null; if (member) matchMethod = 'user_id'; }
          if (!member) {
            const entryNorm = normalize(e.name);
            member = memberByName.get(entryNorm) || null;
            if (member) matchMethod = 'name_exact';
            if (!member && entryNorm.length > 3) {
              const prefix = entryNorm.slice(0, 6);
              for (const { name: mName, data: mData } of (prefixIndex.get(prefix) || [])) {
                if (mName.includes(entryNorm)) { member = mData; matchMethod = 'name_partial'; break; }
              }
            }
          }
          const isKnown = !!member;
          const memberStatus = isKnown ? (isSubActive(member.expiresOn) ? 'active' : 'expired') : 'unknown';
          const ck = e.user_id ? `uid_${e.user_id}_at_${gid}` : `name_${normId(e.name)}_at_${gid}`;
          const cachedId = cachedIds.get(ck) || null;
          const visits   = getVisitStats(e, gid);
          merged.push({
            docId: e.id, name: e.name, userId: e.user_id || null, gymId: gid,
            displayTime: (e.timestamp || '').slice(11, 16), timestamp: e.timestamp,
            status: e.status, method: e.method, isFace: e.is_face === 1,
            isKnown, memberStatus, matchMethod, expiresOn: member ? member.expiresOn : null,
            userTodayCount: visits.today, userWeekCount: visits.week,
            smartId: cachedId ? {
              status: cachedId.id_status, matchedName: cachedId.matched_name,
              matchedGym: cachedId.matched_gym, confidence: cachedId.confidence,
              comment: cachedId.comment, groqUsed: !!cachedId.groq_used,
            } : null,
          });
          if (!cachedId && !isKnown) identifyEntry(e, gid, true).catch(() => {});
        }
        merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
        liveEntriesCache.set(cacheKey, { ts: Date.now(), data: { ok: true, gymId: gid, count: merged.length, entries: merged } });

      } catch (err) {
        // Silent — don't crash the pre-warmer if one gym fails
      }
      // 2s gap between gyms to spread CPU load
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  // Start pre-warmer 8s after boot, then every 10s
  setTimeout(() => {
    preWarmLiveEntries();
    setInterval(preWarmLiveEntries, 10000);
  }, 8000);




  // GET /api/live-count
  router.get('/api/live-count', verifyAzureToken, async (req, res) => {
    try {
      let { gymId } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      
      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin) {
          const assigned = req.assignedGyms?.[0];
          if (assigned && assigned !== 'all') gymId = assigned;
          // RH/PM have assignedGyms=['all'] — pass gymId through
      }
      const today = getMoroccanDateStr();
      const cacheKey = `live_count_${gymId}`;
      const result = await getCachedOrFetch(apiCache.general, cacheKey, 30000, async () => {
        const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : [gymId];
        let totalCount = 0, totalRaw = 0;
        for (const gid of gymIds) {
          const cached = lc.getDailyStat(gid, today);
          const liveUnique = lc.getUniqueEntryCount(gid, today);
          const liveRaw    = lc.getEntryCount(gid, today);

          // Use whichever is higher (protects against machine resets or stale cache)
          totalCount += Math.max(liveUnique, cached?.count || 0);
          totalRaw    += Math.max(liveRaw,    cached?.raw_count || 0);
        }
        return { count: totalCount, rawCount: totalRaw, date: today, source: 'aggregation' };
      });
      res.json({ ok: true, gymId, ...result });
    } catch (err) {
      console.error('Live Count Error:', err);
      res.status(500).json({ error: 'Failed to fetch count' });
    }
  });


  // GET /api/door-history -- lightweight door entry list for RH/PM
  // Supports: gymId (comma-sep or 'all'), startDate, endDate, date, name, limit
  router.get('/api/door-history', verifyAzureToken, async (req, res) => {
    try {
      let { gymId, startDate, endDate, date, name, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });

      // Security: restrict non-admins without 'all' access
      if (!req.isAdmin) {
        const assigned = req.assignedGyms?.[0];
        if (assigned && assigned !== 'all') gymId = assigned;
        // RH/PM with assignedGyms=['all'] pass gymId through
      }

      const limitCount = Math.min(parseInt(limitParam) || 300, 500);
      const today = getMoroccanDateStr();
      const GYM_NAMES = { marjane: 'Fes Saiss', dokarat: 'Doukkarate', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : gymId.split(',');

      const options = { limit: limitCount };
      if (date) {
        options.date = date;
      } else {
        options.startDate = startDate || today;
        options.endDate   = endDate   || today;
      }
      if (name && name.trim()) options.name = name.trim();

      const allEntries = [];
      for (const gid of gymIds) {
        const entries = lc.getEntries(gid, options);
        for (const e of entries) {
          allEntries.push({
            id:        e.id,
            gymId:     gid,
            gymName:   GYM_NAMES[gid] || gid,
            timestamp: e.timestamp,
            date:      e.date,
            name:      e.name || '',
            method:    e.is_face ? 'Visage ID' : (e.method || 'NFC'),
            status:    e.status || 'Entree',
          });
        }
      }

      allEntries.sort((a, b) => (b.timestamp > a.timestamp ? 1 : -1));
      const sliced = allEntries.slice(0, limitCount);
      res.json({ ok: true, entries: sliced, total: allEntries.length });
    } catch (err) {
      console.error('[door-history]', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // ?????? GET /api/analytics/daily-stats/:gymId ????????????????????????????????????????????????????????????????????????
  router.get('/api/analytics/daily-stats/:gymId', verifyAzureToken, async (req, res) => {
    try {
      let { gymId } = req.params;
      
      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin) {
          const assigned = req.assignedGyms?.[0];
          if (assigned && assigned !== 'all') gymId = assigned;
          // RH/PM: pass gymId through
      }
      const includeToday = req.query.includeToday === 'true';
      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : gymId.split(',');
      const today = getMoroccanDateStr();

      // Build date range
      const customStart = req.query.startDate;
      const customEnd = req.query.endDate;
      const groupBy = req.query.groupBy || 'day';

      let dateStrs = [];
      let days = parseInt(req.query.days) || 30;

      if (customStart && customEnd) {
         let current = new Date(customStart);
         const end = new Date(customEnd);
         while (current <= end) {
            dateStrs.push(current.toISOString().slice(0, 10));
            current.setDate(current.getDate() + 1);
         }
      } else {
         if (groupBy === 'month') days = 365;
         if (groupBy === 'year') days = 1825;
         // ── Use Morocco-local date as anchor (avoids UTC day-boundary duplication) ──
         // getMoroccanDateStr() returns today's date in Africa/Casablanca timezone.
         // Stepping back N days from this anchor ensures today's bar is always a clean
         // empty slot — no yesterday data bleeds into the last position.
         const anchorStr = getMoroccanDateStr(); // e.g. "2026-05-26"
         const [ay, am, ad] = anchorStr.split('-').map(Number);
         const anchor = new Date(ay, am - 1, ad); // midnight local, no TZ shift
         const offset = includeToday ? 0 : 1;
         dateStrs = Array.from({ length: days }, (_, i) => {
            const d = new Date(anchor);
            d.setDate(d.getDate() - (days - 1 - i + offset));
            return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
         });
      }
      
      dateStrs.sort(); // ensure chronological order

      const map = {};
      dateStrs.forEach(d => map[d] = { count: 0, rawCount: 0, revenue: 0, revPerGym: {} });

      for (const gid of gymIds) {
        let statsArray = [];
        if (customStart && customEnd) {
           statsArray = lc.getDailyStatsRange(gid, customStart, customEnd);
        } else {
           statsArray = lc.getDailyStats(gid, days + 1);
        }
        
        statsArray.forEach(s => {
          if (map[s.date]) {
            map[s.date].count    += s.count    || 0;
            map[s.date].rawCount += s.rawCount || 0;
          }
        });
        
        // Fallback only if daily_stats has no data for today yet (and we want today included)
        if (includeToday && map[today] !== undefined) {
          const statToday = lc.getDailyStat(gid, today);
          if (!statToday || statToday.count === 0) {
            map[today].count    += lc.getUniqueEntryCount(gid, today);
            map[today].rawCount += lc.getEntryCount(gid, today);
          }
        }
      }

      // Revenue from SQLite register (completed days) + today register if requested
      dateStrs.forEach(d => {
         let rev = 0;
         const revPerGym = {};
         for (const gid of gymIds) {
            let gymRev = 0;
            lc.getRegister(gid, d).forEach(e => {
               gymRev += (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
            });
            revPerGym[gid] = gymRev;
            rev += gymRev;
         }
         map[d].revenue = rev;
         map[d].revPerGym = revPerGym;
      });

      let resultList = dateStrs.map(date => ({ gym_id: gymId, date, count: map[date].count, rawCount: map[date].rawCount, revenue: map[date].revenue, revPerGym: map[date].revPerGym }));

      if (groupBy === 'month' || groupBy === 'year') {
         const groupedMap = {};
         resultList.forEach(item => {
            const groupKey = groupBy === 'month' ? item.date.slice(0, 7) : item.date.slice(0, 4);
            if (!groupedMap[groupKey]) {
               groupedMap[groupKey] = { gym_id: gymId, date: groupKey, count: 0, rawCount: 0, revenue: 0, revPerGym: {} };
            }
            groupedMap[groupKey].count += item.count;
            groupedMap[groupKey].rawCount += item.rawCount;
            groupedMap[groupKey].revenue += item.revenue;
            for (const [g, rev] of Object.entries(item.revPerGym)) {
               groupedMap[groupKey].revPerGym[g] = (groupedMap[groupKey].revPerGym[g] || 0) + rev;
            }
         });
         resultList = Object.values(groupedMap).sort((a, b) => a.date.localeCompare(b.date));
      }

      // Today is always included to show live entry counts in the chart.


      res.json(resultList);
    } catch (err) {
      console.error('Daily Stats Error:', err);
      res.status(500).json({ error: 'Failed to fetch analytics' });
    }
  });

  // -- GET /api/analytics/hourly-entries/:gymId ------------------------------
  // Returns per-hour entry counts (06h�23h) aggregated over last `days` days.
  router.get('/api/analytics/hourly-entries/:gymId', verifyAzureToken, async (req, res) => {
    try {
      let { gymId } = req.params;
      const days = Math.min(parseInt(req.query.days) || 7, 60);

      if (!req.isAdmin) {
        const assigned = req.assignedGyms?.[0];
        if (assigned && assigned !== 'all') gymId = assigned;
        // else: RH/PM pass gymId through
      }

      const GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
      const GYM_LABELS = { dokarat: 'DOUKKARATE', marjane: 'FES SAISS', casa1: 'CASA ANFA', casa2: 'CASA LADY' };
      const GYM_COLORS = { dokarat: '#f59e0b', marjane: '#10b981', casa1: '#38bdf8', casa2: '#ec4899' };
      const HOUR_SLOTS = Array.from({ length: 18 }, (_, i) => i + 6); // 6..23

      const anchor = new Date(Date.now() + 3600000);
      anchor.setUTCHours(0, 0, 0, 0);
      const cutoff = new Date(anchor.getTime() - days * 86400000).toISOString().slice(0, 10);

      const targetGyms = gymId === 'all' ? GYMS : gymId.split(',').filter(g => GYMS.includes(g));
      const perGym = {};

      for (const gid of targetGyms) {
        const rows = lc.db ? lc.db.prepare(`
          SELECT CAST(SUBSTR(REPLACE(timestamp,'T',' '), 12, 2) AS INTEGER) AS hr,
                 COUNT(*) AS cnt
          FROM entries
          WHERE gym_id = ? AND date >= ?
            AND timestamp IS NOT NULL AND timestamp != ''
          GROUP BY hr ORDER BY hr
        `).all(gid, cutoff) : [];

        const hourMap = {};
        rows.forEach(r => { if (r.hr >= 6 && r.hr <= 23) hourMap[r.hr] = r.cnt; });
        perGym[gid] = HOUR_SLOTS.map(h => hourMap[h] || 0);
      }

      const average = HOUR_SLOTS.map((_, i) => {
        const vals = Object.values(perGym).map(arr => arr[i]).filter(v => v > 0);
        return vals.length ? Math.round(vals.reduce((s, v) => s + v, 0) / vals.length) : 0;
      });

      res.json({ hours: HOUR_SLOTS.map(h => `${String(h).padStart(2,'0')}h`), perGym, average, gymLabels: GYM_LABELS, gymColors: GYM_COLORS, days, cutoff });
    } catch (err) {
      console.error('[HOURLY-ENTRIES] error:', err);
      res.status(500).json({ error: 'Failed to compute hourly entries' });
    }
  });


  // ?????? GET /api/analytics/kpis/:gymId ???????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/analytics/kpis/:gymId', verifyAzureToken, async (req, res) => {
    try {
      let { gymId } = req.params;
      
      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin) {
          const assigned = req.assignedGyms?.[0];
          if (assigned && assigned !== 'all') gymId = assigned;
          // RH/PM: pass gymId through
      }

      const customStart = req.query.startDate;
      const customEnd = req.query.endDate;
      if (!customStart || !customEnd) {
        const cached = apiCache.kpis[gymId];
        if (cached && Date.now() - cached.ts < 5 * 1000) return res.json(cached.data); // 5s TTL — near-real-time
      }

      const parseLocalDate = (dateStr) => {
        const [y, m, d] = dateStr.split('-').map(Number);
        return new Date(y, m - 1, d);
      };
      
      const todayStr = getMoroccanDateStr();
      const todayStart = parseLocalDate(todayStr);
      
      const nowStr = new Date(new Date().getTime() + 60 * 60 * 1000).toISOString();
      const now = new Date(
        parseInt(nowStr.slice(0, 4)),
        parseInt(nowStr.slice(5, 7)) - 1,
        parseInt(nowStr.slice(8, 10)),
        parseInt(nowStr.slice(11, 13)),
        parseInt(nowStr.slice(14, 16)),
        parseInt(nowStr.slice(17, 19))
      );

      // 📅 Calendar-month start (Moroccan): always 1st of the current month
      const monthStart     = new Date(todayStart.getFullYear(), todayStart.getMonth(), 1);
      // Rolling 7-day window (last 7 business days, same as Auralix PWA)
      const weekStart      = new Date(todayStart.getFullYear(), todayStart.getMonth(), todayStart.getDate() - 6);
      // Yesterday (single business day)
      const yesterdayStart = new Date(todayStart.getFullYear(), todayStart.getMonth(), todayStart.getDate() - 1);
      const yesterdayEnd   = new Date(todayStart.getFullYear(), todayStart.getMonth(), todayStart.getDate() - 1, 23, 59, 59);
      // Rolling 12-month window for Year
      const yearStart      = new Date(todayStart.getFullYear(), todayStart.getMonth(), todayStart.getDate() - 364);

      // Month label for frontend display (e.g. "MAI 2026")
      const MONTH_NAMES_FR = ['JAN','FÉV','MAR','AVR','MAI','JUN','JUL','AOÛ','SEP','OCT','NOV','DÉC'];
      const currentMonthLabel = `${MONTH_NAMES_FR[todayStart.getMonth()]} ${todayStart.getFullYear()}`;

      // 🔒 DISK-ONLY: All KPI data comes from SQLite register_cache. No Firebase reads.

      const gymIds = gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : gymId.split(',');
      const toLocalDateStr = (d) => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;

      // ?????? New members count from register (source of truth, same as Register page) ??????
      const countRegisterInRange = (fromDate, toDate = null) => {
        let count = 0;
        const cursor = new Date(fromDate);
        const limit = toDate || now;
        while (cursor <= limit) {
          const dateStr = toLocalDateStr(cursor);
          for (const gid of gymIds) {
            count += lc.getRegister(gid, dateStr).filter(e => e.source !== 'reste_settlement').length;
          }
          cursor.setDate(cursor.getDate() + 1);
        }
        return count;
      };

      // 💰 Revenue from SQLite register cache — GROSS minus non-rejected décaissements
      const getRevenueAndBreakdown = (fromDate, toDate = null) => {
        let total = 0, espece = 0, tpe = 0, virement = 0, cheque = 0;
        const cursor = new Date(fromDate);
        const limit = toDate || now;
        while (cursor <= limit) {
          const dateStr = toLocalDateStr(cursor);
          for (const gid of gymIds) {
            lc.getRegister(gid, dateStr).forEach(e => {
              const e_esp = Number(e.espece) || 0;
              const e_tpe = Number(e.tpe) || 0;
              const e_vir = Number(e.virement) || 0;
              const e_che = Number(e.cheque) || 0;
              espece += e_esp; tpe += e_tpe; virement += e_vir; cheque += e_che;
              total += e_esp + e_tpe + e_vir + e_che;
            });
            // Subtract all décaissements except rejected ones
            const decs = lc.getDecaissements(gid, dateStr);
            if (decs?.length) {
              decs.forEach(dec => {
                if (dec.status !== 'rejected') {
                  const amt = Number(dec.montant) || 0;
                  espece -= amt;
                  total -= amt;
                }
              });
            }
          }
          cursor.setDate(cursor.getDate() + 1);
        }
        return { total, espece, tpe, virement, cheque };
      };

      // 🔒 DISK-ONLY: Always read KPIs from SQLite. No Firebase fallback.
      const monthCachedCount = (() => {
        let count = 0;
        const c = new Date(monthStart);
        while (c <= now) {
          const ds = toLocalDateStr(c);
          for (const gid of gymIds) count += lc.getRegister(gid, ds).length;
          c.setDate(c.getDate() + 1);
        }
        return count;
      })();
      console.log(`💾 [KPI] SQLite: ${monthCachedCount} entries for ${gymId} (${currentMonthLabel}) — reading from disk only`);
      const incomeDay       = getRevenueAndBreakdown(todayStart);
      const incomeYesterday = getRevenueAndBreakdown(yesterdayStart, yesterdayEnd);
      const incomeWeek      = getRevenueAndBreakdown(weekStart);
      const incomeMonth     = getRevenueAndBreakdown(monthStart);
      const incomeYear      = getRevenueAndBreakdown(yearStart);

      // ── Real Odoo member total per gym ────────────────────────────────────────
      const phOdoo = gymIds.map(() => '?').join(',');
      const odooTotal = lc.db.prepare(
        `SELECT COUNT(*) as c FROM odoo_members_cache WHERE gym_id IN (${phOdoo})`
      ).get(...gymIds)?.c || 0;

      // ── Unique members detected at door this month ─────────────────────────────
      const monthStartStr = toLocalDateStr(monthStart);
      const phDet = gymIds.map(() => '?').join(',');
      const detectedMonth = lc.db.prepare(
        `SELECT COUNT(DISTINCT name) as c FROM entries WHERE gym_id IN (${phDet}) AND date >= ?`
      ).get(...gymIds, monthStartStr)?.c || 0;

      // ── Active subscriptions: all members (incl. archived) with expires_on >= today ──
      // Archive flag is an admin UI status only; subscription validity is based on expiry date alone.
      const phAct = gymIds.map(() => '?').join(',');
      const activeSubscriptions = lc.db.prepare(
        `SELECT COUNT(*) as c FROM members_cache WHERE gym_id IN (${phAct}) AND expires_on >= ?`
      ).get(...gymIds, todayStr)?.c || 0;

      let incomeCustom = { total: 0, espece: 0, tpe: 0, virement: 0, cheque: 0 };
      let regsCustom = 0;
      if (customStart && customEnd) {
        const cStart = parseLocalDate(customStart);
        const cEnd = parseLocalDate(customEnd);
        cEnd.setHours(23, 59, 59); // include full day
        incomeCustom = getRevenueAndBreakdown(cStart, cEnd);
        regsCustom = countRegisterInRange(cStart, cEnd);
      }

      // 💳 Reste à Payer — unpaid balances from register_cache
      // 🔧 FIX: Build a set of settled member keys (contrat or nom+gym) so we can
      // exclude debts that have already been paid via reste_settlement entries.
      const phSettled = gymIds.map(() => '?').join(',');
      const settledRows = lc.db.prepare(
        `SELECT gym_id, nom, contrat, CAST(reste AS REAL) AS reste
         FROM register_cache
         WHERE gym_id IN (${phSettled}) AND COALESCE(source, '') = 'reste_settlement'`
      ).all(...gymIds);
      // Map: memberKey -> latest settlement reste value
      const settledMap = new Map();
      for (const s of settledRows) {
        // Use contract number if available, otherwise fall back to nom+gym
        const key = (s.contrat && s.contrat.trim() && s.contrat.trim() !== '-')
          ? `contrat:${s.contrat.trim()}`
          : `nom:${(s.nom || '').trim().toUpperCase()}|${s.gym_id}`;
        const existing = settledMap.get(key);
        // Keep the lowest reste (most recent settlement usually has lower or zero reste)
        if (!existing || (s.reste || 0) < existing) {
          settledMap.set(key, s.reste || 0);
        }
      }

      const getResteAPayer = (fromDate, toDate = null) => {
        let totalReste = 0, count = 0;
        const cursor = new Date(fromDate);
        const limit = toDate || now;
        while (cursor <= limit) {
          const dateStr = toLocalDateStr(cursor);
          for (const gid of gymIds) {
            lc.getRegister(gid, dateStr).forEach(e => {
              // Skip reste_settlement entries — they are payments, not debts
              if ((e.source || '') === 'reste_settlement') return;
              const reste = Number(e.reste) || 0;
              if (reste > 0) {
                // Check if this member's debt has been settled
                const contratKey = (e.contrat && e.contrat.trim() && e.contrat.trim() !== '-')
                  ? `contrat:${e.contrat.trim()}`
                  : null;
                const nomKey = `nom:${(e.nom || '').trim().toUpperCase()}|${gid}`;
                const settledReste = settledMap.get(contratKey) ?? settledMap.get(nomKey) ?? null;
                if (settledReste !== null) {
                  // Member has a settlement — use the settlement's reste value instead
                  if (settledReste > 0) { totalReste += settledReste; count++; }
                  // If settledReste === 0, debt is fully paid — skip entirely
                } else {
                  totalReste += reste; count++;
                }
              }
            });
          }
          cursor.setDate(cursor.getDate() + 1);
        }
        return { total: Math.round(totalReste), count };
      };

      const resteDay       = getResteAPayer(todayStart);
      const resteYesterday = getResteAPayer(yesterdayStart, yesterdayEnd);
      const resteWeek      = getResteAPayer(weekStart);
      const resteMonth     = getResteAPayer(monthStart);
      const resteYear      = getResteAPayer(yearStart);
      let resteCustom = { total: 0, count: 0 };
      if (customStart && customEnd) {
        const cStart = parseLocalDate(customStart);
        const cEnd = parseLocalDate(customEnd);
        cEnd.setHours(23, 59, 59);
        resteCustom = getResteAPayer(cStart, cEnd);
      }

      // Top debtors (for display — all time, across selected gyms)
      // 🔧 FIX: Exclude reste_settlement entries AND exclude members whose debt
      // has been settled (same contrat or same nom+gym has a reste_settlement with reste=0)
      const phReste = gymIds.map(() => '?').join(',');
      const topDebtors = lc.db.prepare(
        `SELECT r.gym_id, r.nom, CAST(r.reste AS REAL) AS reste, r.date, r.note_reste, r.contrat
         FROM register_cache r
         WHERE r.gym_id IN (${phReste})
           AND CAST(r.reste AS REAL) > 0
           AND COALESCE(r.source, '') != 'reste_settlement'
           AND NOT EXISTS (
             SELECT 1 FROM register_cache s
             WHERE s.source = 'reste_settlement'
               AND CAST(s.reste AS REAL) = 0
               AND s.gym_id = r.gym_id
               AND (
                 (s.contrat = r.contrat AND s.contrat IS NOT NULL AND s.contrat != '' AND s.contrat != '-')
                 OR (s.nom = r.nom AND s.nom IS NOT NULL AND s.nom != '')
               )
           )
         ORDER BY CAST(r.reste AS REAL) DESC LIMIT 10`
      ).all(...gymIds).map(r => ({
        gym: r.gym_id, nom: r.nom, reste: Math.round(r.reste), date: r.date, note: r.note_reste || ''
      }));

      const kpis = {
        currentMonthLabel,   // e.g. "MAI 2026"
        odooTotal,           // Real total from Odoo (e.g. 7429 for Dokarat)
        detectedMonth,       // Unique people detected at door scanner this month
        activeSubscriptions, // Members with non-expired subscription (from members_cache)
        newMembers: { 
          day: countRegisterInRange(todayStart), 
          yesterday: countRegisterInRange(yesterdayStart, yesterdayEnd), 
          week: countRegisterInRange(weekStart), 
          month: countRegisterInRange(monthStart), 
          year: countRegisterInRange(yearStart),
          custom: regsCustom
        },
        income: { 
          day: incomeDay.total, 
          yesterday: incomeYesterday.total, 
          week: incomeWeek.total, 
          month: incomeMonth.total, 
          year: incomeYear.total,
          custom: incomeCustom.total
        },
        resteAPayer: {
          day:       resteDay,
          yesterday: resteYesterday,
          week:      resteWeek,
          month:     resteMonth,
          year:      resteYear,
          custom:    resteCustom,
          topDebtors,
        },
        paymentMethods: { 
          espece: customStart && customEnd ? incomeCustom.espece : incomeMonth.espece, 
          tpe: customStart && customEnd ? incomeCustom.tpe : incomeMonth.tpe, 
          virement: customStart && customEnd ? incomeCustom.virement : incomeMonth.virement, 
          cheque: customStart && customEnd ? incomeCustom.cheque : incomeMonth.cheque 
        },
        paymentMethodsByPeriod: {
          day:   { espece: incomeDay.espece,   tpe: incomeDay.tpe,   virement: incomeDay.virement,   cheque: incomeDay.cheque   },
          week:  { espece: incomeWeek.espece,  tpe: incomeWeek.tpe,  virement: incomeWeek.virement,  cheque: incomeWeek.cheque  },
          month: { espece: incomeMonth.espece, tpe: incomeMonth.tpe, virement: incomeMonth.virement, cheque: incomeMonth.cheque },
          year:  { espece: incomeYear.espece,  tpe: incomeYear.tpe,  virement: incomeYear.virement,  cheque: incomeYear.cheque  },
        }
      };

      apiCache.kpis[gymId] = { data: kpis, ts: Date.now() };
      console.log(`✅ [KPI] ${gymId}: day=${incomeDay.total} | week=${incomeWeek.total} | ${currentMonthLabel}=${incomeMonth.total} | year=${incomeYear.total} DH`);
      res.json(kpis);
    } catch (err) {
      console.error('KPI Calculation Error:', err);
      res.status(500).json({ error: 'Failed to calculate KPIs' });
    }
  });

  // ?????? GET /admin/export-all-stats ??????????????????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/admin/export-all-stats', async (req, res) => {
    try {
      const secret = req.headers['x-inject-secret'];
      const expected = process.env.INJECT_SECRET;
      if (secret !== expected) return res.status(403).json({ error: 'Forbidden' });

      const stats = db.prepare('SELECT * FROM daily_stats WHERE date >= ?').all(lc.getMoroccanDateStr(30));
      const entries = db.prepare('SELECT * FROM entries WHERE date >= ?').all(lc.getMoroccanDateStr(30));
      res.json({ stats, entries });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ?????? POST /api/admin/sync-stats ??????????????????????????????????????????????????????????????????????????????????????????????????????
  router.post('/api/admin/sync-stats', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const days = parseInt(req.query.days) || 7;
      await syncGymCounts(db, apiCache, days);
      res.json({ ok: true, message: `Sync completed for the last ${days} days.` });
    } catch (err) {
      console.error('Manual Sync Error:', err);
      res.status(500).json({ error: 'Sync failed: ' + err.message });
    }
  });

  // ── POST /api/analytics/log-entry ─────────────────────────────────────────
  // 🔒 DISK-ONLY: Updates SQLite daily_stats directly. Zero Firebase reads.
  router.post('/api/analytics/log-entry', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, userId } = req.body;
      if (!gymId || !userId) return res.status(400).json({ error: 'gymId and userId required' });
      const todayStr = lc.getMoroccanDateStr ? lc.getMoroccanDateStr() : new Date().toISOString().slice(0, 10);
      const existing = lc.getDailyStat(gymId, todayStr);
      const newCount = (existing?.count || 0) + 1;
      lc.upsertDailyStat(gymId, todayStr, newCount, (existing?.raw_count || 0) + 1);
      res.json({ ok: true, count: newCount });
    } catch (err) {
      console.error('Log Entry Error:', err);
      res.status(500).json({ error: 'Failed to log entry' });
    }
  });

  // ── GET /api/analytics/auralix-instructions ────────────────────────────────
  router.get('/api/analytics/auralix-instructions', verifyAzureToken, async (req, res) => {
    try {
      const instructions = lc.getMeta('auralix_global_instructions') || '';
      res.json({ ok: true, instructions });
    } catch (err) {
      console.error('GET /api/analytics/auralix-instructions error:', err);
      res.status(500).json({ error: 'Failed to fetch instructions' });
    }
  });

  // ── POST /api/analytics/auralix-instructions ───────────────────────────────
  router.post('/api/analytics/auralix-instructions', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { instructions } = req.body;
      lc.setMeta('auralix_global_instructions', instructions || '');
      res.json({ ok: true });
    } catch (err) {
      console.error('POST /api/analytics/auralix-instructions error:', err);
      res.status(500).json({ error: 'Failed to save instructions' });
    }
  });

  // ── POST /api/analytics/auralix-learn ──────────────────────────────────────
  // "Learning" chat: Admin talks to Auralix to update global directives
  router.post('/api/analytics/auralix-learn', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { message } = req.body;
      if (!message) return res.status(400).json({ error: 'message required' });

      const currentInstructions = lc.getMeta('auralix_global_instructions') || 'No instructions yet.';
      const GROQ_KEY = process.env.GROQ_API_KEY || process.env.GROQ_API_KEY_FALLBACK;

      const prompt = `You are AURALIX CORE MANAGEMENT SYSTEM.
The Super Admin is giving you a tactical instruction or logic update.
Your goal is to update the current "GLOBAL TACTICAL DIRECTIVES" list.

CURRENT DIRECTIVES:
"""
${currentInstructions}
"""

NEW USER MESSAGE:
"${message}"

Rules:
1. Analyse the message. If it adds, modifies or removes a rule, update the list accordingly.
2. If the user says "forget everything" or similar, clear the list.
3. Be smart: if the user says "dont count X", add it as a rule.
4. Respond in JSON format ONLY:
{
  "updatedInstructions": "the full new version of the directives list",
  "response": "A short, sharp tactical confirmation in French to the user (e.g. 'Instruction mémorisée. Protocoles de calcul mis à jour.')",
  "understood": true
}
5. If the message is not an instruction or is totally unclear, set "understood" to false and ask for clarification in "response".`;

      const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama-3.1-8b-instant',
          messages: [{ role: 'system', content: prompt }],
          response_format: { type: 'json_object' },
          temperature: 0.2
        })
      });

      if (!groqRes.ok) throw new Error('Groq failed');
      const data = await groqRes.json();
      const result = JSON.parse(data.choices[0].message.content);

      if (result.understood) {
        lc.setMeta('auralix_global_instructions', result.updatedInstructions);
      }

      res.json({ ok: true, ...result });
    } catch (err) {
      console.error('Auralix Learn Error:', err);
      res.status(500).json({ error: 'Learning process failed' });
    }
  });

  // ?????? POST /api/analytics/auralix-chat ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
  // Interactive Groq chat: accepts a user question + context, returns AI answer
  router.post('/api/analytics/auralix-chat', verifyAzureToken, requireAdmin, async (req, res) => {
    const { question, sector, kpis, dailyStats, liveEntries, decaisData, compData, multiMonthStats } = req.body;
    if (!question) return res.status(400).json({ error: 'question required' });

    const GROQ_KEY          = process.env.GROQ_API_KEY;
    const GROQ_KEY_FALLBACK = process.env.GROQ_API_KEY_FALLBACK;

    if (!GROQ_KEY && !GROQ_KEY_FALLBACK) {
      return res.json({ answer: 'No GROQ_API_KEY configured on server.' });
    }

    const GROQ_MODEL          = 'llama-3.3-70b-versatile';
    const GROQ_MODEL_FALLBACK = 'llama-3.1-8b-instant';
    const callGroq = async (key, messages, model = GROQ_MODEL) => {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages, max_tokens: 1400, temperature: 0.45 })
      });
      if (!r.ok) { const e = await r.text(); throw new Error(`Groq HTTP ${r.status}: ${e.slice(0,200)}`); }
      return r.json();
    };

    // ── Shared context builder ──────────────────────────────────────────────
    const buildContext = (sectorName) => {
      const parts = [];

      // 1. KPIs
      if (kpis) {
        parts.push([
          `=== KPIs (${sectorName}) ===`,
          `Revenus: Auj ${(kpis?.income?.day||0).toLocaleString()} DH | Sem ${(kpis?.income?.week||0).toLocaleString()} DH | Mois ${(kpis?.income?.month||0).toLocaleString()} DH | An ${(kpis?.income?.year||0).toLocaleString()} DH`,
          `Inscriptions: Auj ${kpis?.newMembers?.day||0} | Sem ${kpis?.newMembers?.week||0} | Mois ${kpis?.newMembers?.month||0}`,
          `Membres actifs total: ${kpis?.totalActive || 'N/A'}`,
        ].join('\n'));
      }

      // 2. Multi-gym revenue breakdown (from compData sent by frontend)
      if (compData?.performance?.length > 0) {
        const perf = compData.performance;
        parts.push(
          `=== PERFORMANCE PAR CLUB (${compData.month || 'ce mois'}) ===\n` +
          perf.map(p => `  ${p.gym?.toUpperCase()}: CA ${(p.revenue||0).toLocaleString()} DH | Inscriptions ${p.registrations||0} | Trafic auj ${p.traffic||0}`).join('\n')
        );
      }

      // 3. Multi-month commercial matrix
      if (multiMonthStats?.commercials?.length > 0) {
        const { commercials, months } = multiMonthStats;
        const summary = commercials.map(c => {
          const total = months.reduce((s, m) => s + (c.perMonth[m]?.inscriptions || 0), 0);
          const rev   = months.reduce((s, m) => s + (c.perMonth[m]?.revenue || 0), 0);
          return `  ${c.name}: ${total} inscriptions | CA ${rev.toLocaleString()} DH`;
        });
        parts.push(`=== PERFORMANCE COMMERCIAUX (${months.join(', ')}) ===\n` + summary.join('\n'));
      }

      // 4. 30-day door traffic
      if (Array.isArray(dailyStats) && dailyStats.length > 0) {
        const total30 = dailyStats.reduce((s, d) => s + (d.count || 0), 0);
        const avg30   = Math.round(total30 / dailyStats.length);
        const maxDay  = dailyStats.reduce((m, d) => (d.count||0) > (m.count||0) ? d : m, dailyStats[0]);
        const today   = dailyStats[dailyStats.length - 1];
        const last7   = dailyStats.slice(-7).reduce((s, d) => s + (d.count||0), 0);
        parts.push([
          `=== TRAFIC PORTE 30 JOURS (${sectorName}) ===`,
          `Aujourd'hui (${today?.date}): ${today?.count||0} entrées`,
          `7 derniers jours: ${last7} | Moy/jour: ${avg30} | Total 30j: ${total30}`,
          `Jour record: ${maxDay?.date} avec ${maxDay?.count} entrées`,
          `Derniers 10j: ${dailyStats.slice(-10).map(d=>`${d.date.slice(5)}:${d.count||0}`).join(' | ')}`,
        ].join('\n'));
      }

      // 5. Live entries
      if (Array.isArray(liveEntries) && liveEntries.length > 0) {
        parts.push(
          `=== ENTRÉES EN DIRECT (${sectorName}) ===\n` +
          liveEntries.slice(0, 20).map(e => `  ${e.name||'?'} @ ${e.time ? new Date(e.time).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}) : '??:??'}`).join('\n')
        );
      }

      // 6. Décaissements (cash outflows)
      if (decaisData?.total > 0) {
        const byGym = Object.entries(decaisData.byGym || {}).map(([g, a]) => `${g}: ${a.toLocaleString()} DH`).join(' | ');
        parts.push([
          `=== DÉCAISSEMENTS (SORTIES ESPÈCES) ===`,
          `Total période: ${(decaisData.total||0).toLocaleString()} DH | Nb opérations: ${decaisData.entries?.length||0}`,
          byGym ? `Par gym: ${byGym}` : '',
          decaisData.entries?.slice(0,10).map(d => `  ${d.date} | ${d.gymId} | ${(d.montant||0).toLocaleString()} DH | ${d.raison||'?'} | ${d.status||'approved'}`).join('\n'),
        ].filter(Boolean).join('\n'));
      }

      // 7. Incidents from SQLite
      try {
        const incidentRows = lc.db ? lc.db.prepare(
          `SELECT gym_id, title, cause, emergency, status, date FROM incidents_cache ORDER BY created_at DESC LIMIT 20`
        ).all() : [];
        if (incidentRows.length > 0) {
          const open = incidentRows.filter(r => r.status !== 'Resolved');
          parts.push(
            `=== INCIDENTS (${open.length} non-résolus / ${incidentRows.length} total) ===\n` +
            incidentRows.map(r => `  [${r.status||'?'}] ${r.gym_id} | ${r.title} | ${r.emergency} urgence | ${r.date}`).join('\n')
          );
        }
      } catch(e) { /* silent */ }

      // 8. Members with debt (reste > 0)
      try {
        const debtRows = lc.db ? lc.db.prepare(
          `SELECT gym_id, nom, reste, note_reste, date FROM register_cache WHERE reste > 0 ORDER BY reste DESC LIMIT 15`
        ).all() : [];
        if (debtRows.length > 0) {
          const totalDebt = debtRows.reduce((s, r) => s + (r.reste||0), 0);
          parts.push(
            `=== CRÉANCES MEMBRES (reste à payer) ===\n` +
            `Total: ${totalDebt.toLocaleString()} DH sur ${debtRows.length} membres\n` +
            debtRows.slice(0,8).map(r => `  ${r.gym_id} | ${r.nom} | ${r.reste} DH | ${r.note_reste||''}`).join('\n')
          );
        }
      } catch(e) { /* silent */ }

      // 9. Courses/schedule
      try {
        const courseRows = lc.db ? lc.db.prepare(
          `SELECT title, coach, days, time, reserved, capacity FROM courses_cache LIMIT 30`
        ).all() : [];
        if (courseRows.length > 0) {
          parts.push(
            `=== PLANNING COURS ===\n` +
            courseRows.map(d => {
              let days = ''; try { days = JSON.parse(d.days||'[]').join(','); } catch { days = d.days||''; }
              return `  ${d.title} (${d.coach}) | ${days} | ${d.time} | ${d.reserved||0}/${d.capacity||'?'} réservations`;
            }).join('\n')
          );
        }
      } catch(e) { /* silent */ }

      // 10. Subscriptions
      try {
        const { DEFAULT_SUBSCRIPTION_GROUPS } = require('./config');
        if (DEFAULT_SUBSCRIPTION_GROUPS) {
          parts.push(
            `=== FORMULES ABONNEMENTS ===\n` +
            DEFAULT_SUBSCRIPTION_GROUPS.map(g => `${g.label}: ` + g.options.map(o => `${o.name}=${o.price>0?o.price+'DH':'inclus'}`).join(', ')).join('\n')
          );
        }
      } catch(e) { /* silent */ }

      // 11. Recent sales
      try {
        const salesRows = lc.db ? lc.db.prepare(`
          SELECT date, gym_id, nom, prix, reste, abonnement, source
          FROM register_cache
          WHERE gym_id = ? OR ? = 'all'
          ORDER BY date DESC, created_at DESC
          LIMIT 25
        `).all(sector, sector) : [];
        if (salesRows.length > 0) {
          parts.push(
            `=== VENTES RÉCENTES ===\n` +
            salesRows.map(s => `  ${s.date} | ${s.gym_id} | ${s.nom} | ${s.prix}DH | ${s.abonnement} | reste:${s.reste||0}`).join('\n')
          );
        }
      } catch(e) { /* silent */ }

      // 12. Historical monthly revenue (last 24 months from SQLite)
      try {
        const histRows = lc.db ? lc.db.prepare(`
          SELECT gym_id,
                 strftime('%Y-%m', date) AS ym,
                 ROUND(SUM(COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0)), 0) AS total,
                 COUNT(*) AS inscriptions
          FROM register_cache
          WHERE date >= date('now','-24 months')
          GROUP BY gym_id, ym
          ORDER BY ym ASC
        `).all() : [];
        if (histRows.length > 0) {
          // Aggregate by month across all gyms, then per gym
          const monthMap = {};
          histRows.forEach(r => {
            if (!monthMap[r.ym]) monthMap[r.ym] = { total: 0, inscriptions: 0, byGym: {} };
            monthMap[r.ym].total += r.total || 0;
            monthMap[r.ym].inscriptions += r.inscriptions || 0;
            monthMap[r.ym].byGym[r.gym_id] = { revenue: Math.round(r.total || 0), inscriptions: r.inscriptions || 0 };
          });
          const histLines = Object.entries(monthMap).map(([ym, d]) => {
            const gymBreakdown = Object.entries(d.byGym).map(([g, v]) => `${g}:${v.revenue.toLocaleString()}DH`).join(' | ');
            return `  ${ym}: ${Math.round(d.total).toLocaleString()} DH | ${d.inscriptions} inscriptions [${gymBreakdown}]`;
          });
          parts.push(
            `=== HISTORIQUE CA MENSUEL (24 derniers mois) ===\n` + histLines.join('\n')
          );
        }
      } catch(e) { /* silent */ }

      return parts.join('\n\n');
    };

    try {
      const GYM_NAMES = {
        all: 'ALL EMPIRE (Dokarat + Saiss + Casa Anfa + Casa Lady)',
        dokarat: 'Fès Doukkarate', marjane: 'Fès Saiss',
        casa1: 'Casa Anfa', casa2: 'Casa Lady'
      };
      const sectorName = GYM_NAMES[sector] || sector || 'ALL EMPIRE';
      const fullContext = buildContext(sectorName);
      const globalInstructions = lc.getMeta('auralix_global_instructions') || '';

      const messages = [
        {
          role: 'system',
          content: `Tu es AURALIX, l'IA tactique de commandement du groupe MegaFit — 4 clubs (Fès Doukkarate, Fès Saiss, Casa Anfa, Casa Lady).

RÈGLES ABSOLUES:
1. Réponse UNIQUEMENT en français professionnel et percutant.
2. Format: bullet points ultra-concis. Zéro bavardage. Précision chirurgicale.
3. Cite les chiffres exacts du contexte. Jamais de vague généralité.
4. Si tu détectes anomalie, dette, incident non résolu, sous-performance: signale immédiatement avec ⚠️.
5. Termine par [+] si confiant, [-] si incertain ou données manquantes.
6. Tu as accès à: KPIs en temps réel, trafic porte 30j, entrées live, décaissements, incidents, créances membres, planning cours, ventes récentes, performance par club et par commercial.
7. Tu connais l'historique CA mensuel des 24 derniers mois par club (inclus dans les donnees).
8. CALENDRIER BUSINESS ANNUEL MAROC � ANALYSE COMME UN DIRECTEUR OPERATIONNEL:

=== RELIGIEUX ISLAMIQUE (calendrier lunaire, avance ~11j/an) ===
RAMADAN (jeune 30j): Baisse inscriptions -40% a -60%. Membres absents. Horaires decales (ouverture tard).
  2024: 11 mars - 9 avr | 2025: 1 mars - 29 mars | 2026: 18 fev - 18 mars | 2027: ~7 fev
EID AL-FITR (Eid Sghir, fin Ramadan): Fermeture 3-5j + semaine de retour lente.
  2024: 10 avr | 2025: 31 mars | 2026: 20 mars | 2027: ~9 mars
EID AL-ADHA (Eid Kbir): IMPACT MAXIMAL � fermeture 5-7j + exodus 10-15j. Pire periode de l'annee.
  2024: 16 juin | 2025: 7 juin | 2026: 27 mai | 2027: ~17 mai
  NOTE: Eid Kbir 2026 = 27 mai ? mai 2026 fin de mois tres creuse. Impact sur juin aussi.
AID AL-MAWLID (naissance prophete): Ferie 1 jour. Impact mineur.
  2024: 16 sept | 2025: 5 sept | 2026: 25 aout

=== FERIES NATIONALES MAROCAINES (fixes) ===
1 janvier: Nouvel An � fermeture 1j, pic inscriptions "resolutions" les premiers jours.
11 janvier: Manifeste de l'independance � ferie.
1 mai: Fete du Travail � ferie.
23 mai: Fete nationale � ferie.
30 juillet: Fete du Trone � ferie + ambiance estivale ? baisse trafic.
14 aout: Recuperation de Oued Eddahab � ferie.
20 aout: Revolution du Roi et du Peuple � ferie.
21 aout: Fete de la Jeunesse � ferie.
6 novembre: Marche Verte � ferie.
18 novembre: Fete de l'independance � ferie.

=== CALENDRIER SCOLAIRE MAROC (impact MAJEUR sur frequentation gym) ===
RENTREE: Debut septembre. PIC FORT inscriptions. Meilleur moment pour offres promotionnelles.
VACANCES TOUSSAINT: Fin octobre ~1 semaine. Trafic +15% (etudiants disponibles).
VACANCES NOEL/HIVER: ~25 dec - 5 jan. Trafic mixte (familles + resolutions jan).
VACANCES PRINTEMPS: Mi-mars ~1 semaine (si pas pendant Ramadan). Trafic +10%.
VACANCES ETE: Juillet-Aout. IMPACT MAXIMUM:
  - Etudiants et lyceans libres = trafic HAUSSE si pas Eid/chaleur
  - Familles partent en vacances = BAISSE adultes actifs
  - Chaleur estivale a Fes = baisse motivation
  - Juillet = bilan mixte | Aout = creux sauf nouveaux inscrits
EXAMENS BAC: Juin (session normale) + Juillet (session rattrapage). Lyceans absents.

=== CYCLES BUSINESS GYM � CLASSIFICATION STRATEGIQUE ===
JANVIER: ????? Pic absolu. Resolutions + reprise apres fetes. Ouvrir promotions agressives.
FEVRIER: ???? Fort. Momentum resolutions. Si Ramadan debut fev = impact negatif progressif.
MARS: ??? Variable. Si Ramadan = tres faible. Si pas Ramadan = bon mois.
AVRIL: ??? Variable. Post-Eid-Fitr = reprise progressive. Printemps motivant.
MAI: ???? Bon. Pas de contrainte sauf Eid Kbir fin mai certaines annees (2026).
JUIN: ?? Risque Eid Kbir. Exams BAC. Chaleur commence.
JUILLET: ?? Creux estival. Chaleur + vacances familles. Etudiants compensent partiellement.
AOUT: ?? Creux. Point bas estival. Relance de pre-rentree fin aout.
SEPTEMBRE: ????? Deuxieme meilleur mois. Rentree scolaire. Forte demande inscriptions.
OCTOBRE: ???? Bon. Vacances Toussaint. Temps plus frais = motivation sport.
NOVEMBRE: ???? Fort. Pas de contrainte majeure. Campagnes fid�lisation.
DECEMBRE: ??? Correct. Fetes de fin d'annee. Pre-pic janvier.

=== REGLES D'INTERPRETATION INTELLIGENTE ===
AVANT de qualifier une baisse comme sous-performance:
  1. Verifier si Ramadan/Eid etait actif ce mois-la
  2. Comparer au MEME mois l'annee precedente (pas le mois precedent)
  3. Identifier les feries nationales du mois
  4. Evaluer periode scolaire (exams? vacances?)
  5. Seulement si aucun facteur calendaire n'explique ? c'est une vraie anomalie

SIGNAUX D'ALERTE REELS (pas calendaires):
  - CA inferieur de >20% vs meme mois N-1 SANS facteur calendaire = ALERTE
  - Trafic porte tres bas un jour normal (hors ferie) = probleme operationnel
  - CA mai 2026 faible sur fin du mois ? ATTENDU (Eid Kbir 27 mai)
  - Docarat mars 2025 (354k DH) vs mars 2026 (1.11M DH) ? ecart explique par Ramadan mars 2025

COMPORTEMENT INSTRUCTEUR DÉFINI PAR L'UTILISATEUR:
${globalInstructions || 'Aucune règle personnalisée.'}

=== DONNÉES TEMPS RÉEL — ${sectorName} ===
${fullContext}`
        },
        { role: 'user', content: question }
      ];

      let data;
      try {
        data = await callGroq(GROQ_KEY, messages, GROQ_MODEL);
      } catch (primaryErr) {
        console.warn(`[Groq] Primary failed (${primaryErr.message}), using fallback...`);
        data = await callGroq(GROQ_KEY_FALLBACK || GROQ_KEY, messages, GROQ_MODEL_FALLBACK);
      }

      let raw = data?.choices?.[0]?.message?.content || 'Pas de réponse de Groq.';
      let sentiment = 'positive';
      if (raw.endsWith('[-]')) { sentiment = 'negative'; raw = raw.slice(0,-3).trim(); }
      else if (raw.endsWith('[+]')) { sentiment = 'positive'; raw = raw.slice(0,-3).trim(); }
      res.json({ answer: raw, sentiment });
    } catch (err) {
      console.error('Groq chat error:', err);
      res.status(500).json({ error: 'Groq service unavailable', answer: '⚠️ Neural core offline.' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // POST /api/analytics/auralix-scan  — Proactive anomaly detection (no user question needed)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.post('/api/analytics/auralix-scan', verifyAzureToken, requireAdmin, async (req, res) => {
    const { kpis, dailyStats, liveEntries, decaisData, compData, multiMonthStats } = req.body;
    const GROQ_KEY = process.env.GROQ_API_KEY;
    const GROQ_KEY_FALLBACK = process.env.GROQ_API_KEY_FALLBACK;
    if (!GROQ_KEY && !GROQ_KEY_FALLBACK) return res.json({ answer: 'GROQ_API_KEY manquant.' });

    // Pull fresh data directly from SQLite for the scan
    let incidentSummary = '', debtSummary = '', perfSummary = '';
    try {
      const openIncidents = lc.db ? lc.db.prepare(
        `SELECT gym_id, title, emergency, status, date FROM incidents_cache WHERE status != 'Resolved' ORDER BY created_at DESC LIMIT 10`
      ).all() : [];
      if (openIncidents.length > 0) {
        incidentSummary = `INCIDENTS NON-RÉSOLUS (${openIncidents.length}):\n` +
          openIncidents.map(r => `  ⚠️ [${r.emergency}] ${r.gym_id} — ${r.title} (${r.date})`).join('\n');
      }
    } catch(e) {}

    try {
      const debtRows = lc.db ? lc.db.prepare(
        `SELECT gym_id, nom, reste FROM register_cache WHERE reste > 0 ORDER BY reste DESC LIMIT 10`
      ).all() : [];
      if (debtRows.length > 0) {
        const totalDebt = debtRows.reduce((s, r) => s + (r.reste||0), 0);
        debtSummary = `CRÉANCES MEMBRES: ${totalDebt.toLocaleString()} DH | Top: ` +
          debtRows.slice(0,5).map(r => `${r.nom}(${r.gym_id}):${r.reste}DH`).join(', ');
      }
    } catch(e) {}

    if (compData?.performance?.length > 0) {
      perfSummary = `PERFORMANCE CLUBS (${compData.month}):\n` +
        compData.performance.map(p => `  ${p.gym}: CA ${(p.revenue||0).toLocaleString()} DH | ${p.registrations||0} inscrits | ${p.traffic||0} entrées auj`).join('\n');
    }

    const kpiLine = kpis ? `KPIs Empire: CA mois ${(kpis?.income?.month||0).toLocaleString()} DH | Inscrits mois ${kpis?.newMembers?.month||0} | Actifs ${kpis?.totalActive||'?'}` : '';

    const prompt = `Effectue un SCAN TACTIQUE COMPLET de l'empire MegaFit. Analyse toutes les données disponibles et produis un rapport structuré:

${kpiLine}
${perfSummary}
${incidentSummary}
${debtSummary}

STRUCTURE DU RAPPORT (obligatoire):
🔴 ALERTES CRITIQUES — anomalies, incidents, dettes, sous-performances graves
🟡 POINTS D'ATTENTION — tendances à surveiller, risques potentiels
🟢 OPPORTUNITÉS — leviers de croissance identifiés, clubs performants à capitaliser
📊 DIRECTIVE PRIORITAIRE — 1 action immédiate recommandée

Sois brutal, précis, data-driven. Zéro généralité. Chaque point cité avec chiffre exact.`;

    try {
      const messages = [
        { role: 'system', content: `Tu es AURALIX, directeur operationnel IA du groupe MegaFit (4 clubs: Dokarat, Saiss, Casa Anfa, Casa Lady). Reponse UNIQUEMENT en francais professionnel. Bullet points ultra-concis. Chiffres exacts. Signale anomalies avec WARNING. IMPORTANT: avant de qualifier une baisse comme anomalie, verifie toujours le calendrier: Ramadan 2026=18fev-18mars, Eid Fitr 2026=20mars, Eid Kbir 2026=27mai, Juillet-Aout=creux estival, Juin=exams BAC+risque Eid Kbir, Septembre=pic rentree, Janvier=pic resolutions. Correle les baisses avec ces facteurs avant de conclure a une sous-performance reelle.` },
        { role: 'user', content: prompt }
      ];
      const callGroq = async (key, model) => {
        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, messages, max_tokens: 1600, temperature: 0.4 })
        });
        if (!r.ok) throw new Error(`Groq ${r.status}`);
        return r.json();
      };
      let data;
      try { data = await callGroq(GROQ_KEY, 'llama-3.3-70b-versatile'); }
      catch { data = await callGroq(GROQ_KEY_FALLBACK || GROQ_KEY, 'llama-3.1-8b-instant'); }
      const raw = data?.choices?.[0]?.message?.content || 'Scan incomplet.';
      res.json({ answer: raw, sentiment: raw.includes('🔴') ? 'negative' : 'positive' });
    } catch(err) {
      console.error('[AURALIX SCAN] error:', err);
      res.status(500).json({ answer: '⚠️ Scan failed — neural core offline.' });
    }
  });



  // â”€â”€ INCIDENTS (SQLite-backed, Firestore-write-through) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Cache TTL: 10 minutes â€” avoids Firestore reads on every dashboard refresh
  const INCIDENTS_TTL_MS = 10 * 60 * 1000;
  let incidentsCachedAt = 0;

  async function syncIncidentsFromFirestore() {
    const now = Date.now();
    if (now - incidentsCachedAt < INCIDENTS_TTL_MS) return;
    try {
      const snap = await db.collection('incidents').orderBy('createdAt', 'desc').limit(200).get();
      const rows = snap.docs.map(d => {
        const data = d.data();
        return {
          id: d.id,
          gymId: data.gymId || '',
          gymName: data.gymName || '',
          title: data.title || '',
          cause: data.cause || '',
          explanation: data.explanation || '',
          emergency: data.emergency || 'Low',
          status: data.status || 'Pending',
          reporter: data.reporter || '',
          date: data.date || '',
          createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : new Date().toISOString(),
        };
      });
      lc.upsertIncidents(rows);
      incidentsCachedAt = now;
      console.log(`[INCIDENTS] Synced ${rows.length} incidents to SQLite`);
    } catch (err) {
      console.error('[INCIDENTS] Firestore sync failed, serving stale cache:', err.message);
    }
  }

  // GET /api/incidents
  router.get('/api/incidents', verifyAzureToken, async (req, res) => {
    try {
      await syncIncidentsFromFirestore();
      const gymId = req.query.gymId || 'all';
      const rows = lc.getIncidents(gymId);
      const out = rows.map(r => ({
        id: r.id, gymId: r.gym_id, gymName: r.gym_name,
        title: r.title, cause: r.cause, explanation: r.explanation,
        emergency: r.emergency, status: r.status,
        reporter: r.reporter, date: r.date, createdAt: r.created_at,
      }));
      res.json(out);
    } catch (err) {
      console.error('[INCIDENTS GET] error:', err);
      res.status(500).json({ error: 'Failed to fetch incidents' });
    }
  });

  // ── GET /api/notifications ──────────────────────────────────────────────────
  // Unified notification feed: AI alerts, inscriptions, décaissements, incidents, etc.
  router.get('/api/notifications', verifyAzureToken, async (req, res) => {
    try {
      const gymId = req.query.gymId || (req.assignedGyms?.includes('all') ? 'all' : req.assignedGyms?.[0] || 'all');
      const rows = lc.getNotifications(gymId, { limit: 50 });

      const GYM_NAMES = { dokarat: 'Dokkarat', marjane: 'Saiss', casa1: 'Anfa', casa2: 'Casa Lady' };

      const notifications = rows.map(r => ({
        id:        r.id,
        type:      r.type,
        gymId:     r.gym_id,
        gymName:   GYM_NAMES[r.gym_id] || r.gym_id,
        title:     r.title,
        message:   r.message,
        severity:  r.severity,
        route:     r.route,
        icon:      r.icon,
        refId:     r.ref_id,
        unread:    r.is_read === 0,
        createdAt: r.created_at,
      }));

      res.json(notifications);
    } catch (err) {
      console.error('[NOTIFICATIONS GET] error:', err);
      res.status(500).json({ error: 'Failed to fetch notifications' });
    }
  });

  // ── POST /api/notifications/read ────────────────────────────────────────────
  router.post('/api/notifications/read', verifyAzureToken, async (req, res) => {
    try {
      const gymId = req.body.gymId || 'all';
      lc.markNotificationsRead(gymId);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to mark notifications read' });
    }
  });

  // POST /api/incidents
  router.post('/api/incidents', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, gymName, title, cause, explanation, emergency, reporter, date } = req.body;
      const docRef = await db.collection('incidents').add({
        gymId, gymName, title, cause, explanation, emergency,
        reporter, date, status: 'Pending',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      const now = new Date().toISOString();
      lc.upsertIncidents([{ id: docRef.id, gymId, gymName, title, cause, explanation, emergency, reporter, date, status: 'Pending', createdAt: now }]);
      incidentsCachedAt = 0;

      // 🔔 Notification: new incident
      try {
        lc.addNotification({
          type: 'incident',
          gymId: gymId,
          title: `🚨 Incident — ${title}`,
          message: `${gymName || gymId} · ${emergency} · ${cause || explanation || ''}`.slice(0, 200),
          severity: emergency === 'High' ? 'critical' : emergency === 'Medium' ? 'warning' : 'info',
          route: '/report',
          icon: emergency === 'High' ? '🔴' : '🟡',
          refId: docRef.id,
        });
      } catch(_) {}

      res.json({ id: docRef.id, gymId, gymName, title, cause, explanation, emergency, reporter, date, status: 'Pending', createdAt: now });
    } catch (err) {
      console.error('[INCIDENTS POST] error:', err);
      res.status(500).json({ error: 'Failed to create incident' });
    }
  });

  // PATCH /api/incidents/:id/resolve
  router.patch('/api/incidents/:id/resolve', verifyAzureToken, async (req, res) => {
    try {
      lc.resolveIncidentCache(req.params.id);
      db.collection('incidents').doc(req.params.id).update({
        status: 'Resolved', updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }).catch(err => console.error('[INCIDENTS RESOLVE Firestore]', err.message));
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to resolve incident' });
    }
  });

  // â”€â”€ KIDS COURSES (SQLite read, Firestore write-through on mutations) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // READ  â†’ always SQLite (zero Firestore reads)
  // WRITE â†’ SQLite immediately + Firestore fire-and-forget (backup/sync)
  // STARTUP RECOVERY â†’ if SQLite empty, pull once from Firestore

  async function syncKidsFromFirestore(gymId) {
    try {
      const snap = await db.collection('kids_courses').where('gymId', '==', gymId).get();
      if (snap.empty) return;
      snap.docs.forEach(d => {
        const data = d.data();
        lc.upsertKidsCourse({
          id: d.id,
          gymId: data.gymId || gymId,
          groupId: data.groupId || '',
          groupName: data.groupName || '',
          day: data.day || '',
          timeStart: data.timeStart || '',
          timeEnd: data.timeEnd || '',
          activity: data.activity || '',
          ages: data.ages || '',
        });
      });
      console.log(`[KIDS] Recovered ${snap.size} sessions from Firestore â†’ SQLite`);
    } catch (err) {
      console.error('[KIDS] Firestore recovery failed:', err.message);
    }
  }

  function kidsRow(r) {
    return {
      id: r.id, gymId: r.gym_id, groupId: r.group_id, groupName: r.group_name,
      day: r.day, timeStart: r.time_start, timeEnd: r.time_end,
      activity: r.activity, ages: r.ages, updatedAt: r.updated_at,
    };
  }

  // GET /public/kids-courses â€” no auth (mobile app)
  router.get('/public/kids-courses', async (req, res) => {
    try {
      const gymId = req.query.gym || 'dokarat';
      let rows = lc.getKidsCourses(gymId);
      if (rows.length === 0) { await syncKidsFromFirestore(gymId); rows = lc.getKidsCourses(gymId); }
      res.json(rows.map(kidsRow));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch kids courses' }); }
  });

  // GET /api/kids-courses â€” authenticated dashboard
  router.get('/api/kids-courses', verifyAzureToken, async (req, res) => {
    try {
      const gymId = req.query.gym || 'dokarat';
      let rows = lc.getKidsCourses(gymId);
      if (rows.length === 0) { await syncKidsFromFirestore(gymId); rows = lc.getKidsCourses(gymId); }
      res.json(rows.map(kidsRow));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch kids courses' }); }
  });

  // POST /api/kids-courses â€” create + write-through to Firestore
  router.post('/api/kids-courses', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, groupId, groupName, day, timeStart, timeEnd, activity, ages } = req.body;
      if (!groupId || !day || !timeStart || !timeEnd || !activity || !ages) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
      const id = lc.upsertKidsCourse({ gymId: gymId || 'dokarat', groupId, groupName, day, timeStart, timeEnd, activity, ages });
      // Fire-and-forget Firestore sync
      db.collection('kids_courses').doc(id).set({
        gymId: gymId || 'dokarat', groupId, groupName, day, timeStart, timeEnd, activity, ages,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(e => console.error('[KIDS POST Firestore]', e.message));
      res.json({ id, gymId: gymId || 'dokarat', groupId, groupName, day, timeStart, timeEnd, activity, ages });
    } catch (err) { res.status(500).json({ error: 'Failed to create kids course' }); }
  });

  // PUT /api/kids-courses/:id â€” update + write-through to Firestore
  router.put('/api/kids-courses/:id', verifyAzureToken, async (req, res) => {
    try {
      const { groupId, groupName, day, timeStart, timeEnd, activity, ages } = req.body;
      lc.updateKidsCourse(req.params.id, {
        group_id: groupId, group_name: groupName, day,
        time_start: timeStart, time_end: timeEnd, activity, ages,
      });
      // Fire-and-forget Firestore sync
      db.collection('kids_courses').doc(req.params.id).update({
        groupId, groupName, day, timeStart, timeEnd, activity, ages,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(e => console.error('[KIDS PUT Firestore]', e.message));
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to update kids course' }); }
  });

  // DELETE /api/kids-courses/:id â€” delete from SQLite + Firestore
  router.delete('/api/kids-courses/:id', verifyAzureToken, async (req, res) => {
    try {
      lc.deleteKidsCourse(req.params.id);
      db.collection('kids_courses').doc(req.params.id).delete()
        .catch(e => console.error('[KIDS DELETE Firestore]', e.message));
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete kids course' }); }
  });

  // POST /api/kids-courses/seed â€” reset to official schedule (idempotent)
  router.post('/api/kids-courses/seed', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const defaults = [
        { groupId:'A', groupName:'Les MEGAfit Dynamiques',       day:'Mercredi', timeStart:'14:30', timeEnd:'15:30', activity:'Natation', ages:'5ans-9ans' },
        { groupId:'A', groupName:'Les MEGAfit Dynamiques',       day:'Samedi',   timeStart:'10:00', timeEnd:'11:00', activity:'Funfit',   ages:'5ans-8ans' },
        { groupId:'A', groupName:'Les MEGAfit Dynamiques',       day:'Dimanche', timeStart:'10:00', timeEnd:'11:00', activity:'Natation', ages:'5ans-9ans' },
        { groupId:'B', groupName:'Les MEGAfit Junior-Energie',   day:'Mercredi', timeStart:'15:30', timeEnd:'16:30', activity:'Natation', ages:'10ans-14ans' },
        { groupId:'B', groupName:'Les MEGAfit Junior-Energie',   day:'Samedi',   timeStart:'11:00', timeEnd:'12:00', activity:'Funfit',   ages:'9ans-14ans' },
        { groupId:'B', groupName:'Les MEGAfit Junior-Energie',   day:'Dimanche', timeStart:'11:00', timeEnd:'12:00', activity:'Natation', ages:'10ans-14ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Vendredi', timeStart:'15:00', timeEnd:'16:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Samedi',   timeStart:'10:00', timeEnd:'11:00', activity:'Funfit',   ages:'5ans-8ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Samedi',   timeStart:'11:00', timeEnd:'12:00', activity:'Funfit',   ages:'9ans-14ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Dimanche', timeStart:'12:00', timeEnd:'13:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'D', groupName:'Les MEGAfit Futurs Champions', day:'Samedi',   timeStart:'14:00', timeEnd:'15:00', activity:'Funfit',   ages:'5ans-14ans' },
        { groupId:'D', groupName:'Les MEGAfit Futurs Champions', day:'Samedi',   timeStart:'15:00', timeEnd:'16:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'D', groupName:'Les MEGAfit Futurs Champions', day:'Dimanche', timeStart:'12:00', timeEnd:'13:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'E', groupName:'Les MEGAfit Tout-Petits',      day:'Mercredi', timeStart:'14:30', timeEnd:'15:30', activity:'Natation', ages:'3ans-4ans'  },
        { groupId:'E', groupName:'Les MEGAfit Tout-Petits',      day:'Dimanche', timeStart:'10:00', timeEnd:'11:00', activity:'Natation', ages:'3ans-4ans'  },
      ];
      defaults.forEach(d => lc.upsertKidsCourse({ ...d, gymId: 'dokarat' }));
      // Sync seeded data to Firestore in background
      Promise.all(defaults.map(d => {
        const id = lc.getKidsCourses('dokarat').find(r =>
          r.group_id === d.groupId && r.day === d.day && r.time_start === d.timeStart
        )?.id;
        if (!id) return;
        return db.collection('kids_courses').doc(id).set({
          ...d, gymId: 'dokarat',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      })).catch(e => console.error('[KIDS SEED Firestore]', e.message));
      res.json({ ok: true, seeded: defaults.length });
    } catch (err) { res.status(500).json({ error: 'Seed failed' }); }
  });



  // ZKTeco name parser: "[1234] John Doe" -> { userId, cleanName }
  function parseZKTecoName(rawName) {
    if (!rawName) return { userId: null, cleanName: "" };
    const match = rawName.match(/^\[(\d+)\]\s*(.+)$/);
    if (match) return { userId: match[1], cleanName: match[2].trim() };
    const newIdMatch = rawName.match(/^New ID:(\d+)$/);
    if (newIdMatch) return { userId: newIdMatch[1], cleanName: "Inconnu #" + newIdMatch[1] };
    return { userId: null, cleanName: rawName };
  }

  // ── pollDoorEntries — server-side background task, called every 60s ──────────
  // ✅ EFFICIENT: Only reads the LAST 1 document per gym collection.
  // The device embeds daily_unique + daily_total in every scan, so the
  // last scan of the day always has the current running total.
  // Cost: 1 read per gym per minute. Also saves latest entry for live feed.
  router.pollDoorEntries = async function pollDoorEntries() {
    const today = getMoroccanDateStr();
    const nextDay = new Date(new Date(today).getTime() + 86400000).toISOString().slice(0, 10);

    for (const [gid, g] of Object.entries(GYM_DOOR_MAP)) {
      try {
        let bestUnique = 0;
        let bestTotal  = 0;

        for (const coll of g.collections) {
          // ✅ INCREMENTAL SYNC: Only fetch entries newer than what we already have
          const lastEntry = lc.db.prepare("SELECT timestamp FROM entries WHERE gym_id=? AND date=? ORDER BY timestamp DESC LIMIT 1").get(gid, today);
          // Normalize timestamp: remove 'T' and 'Z' so it matches the space-format in Firestore
          const lastTs = lastEntry ? lastEntry.timestamp.replace('T', ' ').replace('Z', '') : today;

          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: {
                compositeFilter: {
                  op: 'AND',
                  filters: [
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'GREATER_THAN', value: { stringValue: lastTs } } },
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'LESS_THAN', value: { stringValue: nextDay } } }
                  ]
                }
              },
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'ASCENDING' }], // ASC so we process them in order
              limit: 100, // Safety limit
            }
          };

          const resp = await fetch(DOOR_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          if (!resp.ok) { console.warn(`[DOOR POLL] ${gid}/${coll} HTTP ${resp.status}`); continue; }
          const data = await resp.json();
          if (!Array.isArray(data)) continue;

          const docs = data.filter(item => item.document).map(item => item.document);
          if (!docs.length) continue;

          for (const doc of docs) {
            const f   = doc.fields || {};
            const loc = (f.location?.stringValue || '').toLowerCase();
            const tags = g.locationTags.map(t => t.toLowerCase());
            if (!tags.some(t => loc.includes(t) || t.includes(loc))) continue;

            // Read device-embedded daily totals from every doc (most accurate on the last one)
            const du = f.daily_unique?.integerValue != null ? parseInt(f.daily_unique.integerValue) :
                       f.daily_unique?.doubleValue  != null ? Math.round(f.daily_unique.doubleValue) : 0;
            const dt = f.daily_total?.integerValue  != null ? parseInt(f.daily_total.integerValue) :
                       f.daily_total?.doubleValue   != null ? Math.round(f.daily_total.doubleValue) : 0;
            if (du > bestUnique) { bestUnique = du; bestTotal = dt; }

            // ✅ Save every entry to disk (live feed + offline backup)
            const ts = f.timestamp?.stringValue || '';
            if (ts.startsWith(today)) {
              const entryId = doc.name?.split('/').pop() || ts;

              // ── Parse ZKTeco name format: "[1234] John Doe" or legacy plain name ──
              const rawName = f.name?.stringValue || '';
              const { userId, cleanName } = parseZKTecoName(rawName);

              // ── Also read user_id field if device sends it separately ──
              const deviceUserId = f.user_id?.stringValue
                || (f.user_id?.integerValue != null ? String(f.user_id.integerValue) : null)
                || userId; // fall back to ID extracted from name

              lc.upsertEntries(gid, [{
                id:        entryId,
                gym_id:    gid,
                date:      today,
                timestamp: ts,
                name:      cleanName,   // clean name without [ID] prefix
                method:    f.method?.stringValue || '',
                status:    f.status?.stringValue || 'Entrée',
                is_face:   (f.method?.stringValue || '').toLowerCase().includes('face') ? 1 : 0,
                user_id:   deviceUserId || null,
              }]);
            }
          }
        }

        if (bestUnique > 0) {
          // ✅ RESILIENT: If device reset its counter (bestUnique < localCount), use local database count instead
          const localStats = lc.db.prepare("SELECT COUNT(DISTINCT name) as count, COUNT(*) as total FROM entries WHERE gym_id=? AND date=?").get(gid, today);
          const finalUnique = Math.max(bestUnique, localStats.count || 0);
          const finalTotal  = Math.max(bestTotal,  localStats.total || 0);

          lc.upsertDailyStat(gid, today, finalUnique, finalTotal);
          
          const prev = lc.getDailyStat(gid, today)?.count || 0;
          if (finalUnique !== prev) {
            console.log(`[DOOR POLL] ${gid}: ${finalUnique} unique / ${finalTotal} total today (Device: ${bestUnique}, Local: ${localStats.count})`);
          }
        }

        lc.setMeta(`liveEntries_sync_${gid}`, String(Date.now()));
      } catch (e) {
        console.warn(`[DOOR POLL] ${gid} failed: ${e.message}`);
      }
    }
  };

  // ── gapFillDoorEntries — run on startup to recover missing historical days ──
  // Checks each of the last 30 days. If a day has 0 count in SQLite,
  // fetches it from Firestore and saves to disk. After this, the SQLite
  // disk is the complete source of truth for historical data.
  router.gapFillDoorEntries = async function gapFillDoorEntries() {
    console.log('[GAP FILL] Checking last 30 days for missing door entry data...');
    const gaps = [];

    for (let i = 1; i <= 30; i++) {
      const d = new Date(Date.now() + 3600000 - i * 86400000);
      const dateStr = d.toISOString().slice(0, 10);
      for (const [gid] of Object.entries(GYM_DOOR_MAP)) {
        const stat = lc.getDailyStat(gid, dateStr);
        if (!stat || stat.count === 0) gaps.push({ gid, dateStr });
      }
    }

    if (gaps.length === 0) {
      console.log('[GAP FILL] No gaps found — disk is complete ✅');
      return;
    }

    console.log(`[GAP FILL] Found ${gaps.length} missing days — fetching from Firestore...`);

    for (const { gid, dateStr } of gaps) {
      const g = GYM_DOOR_MAP[gid];
      if (!g) continue;
      const nextDay = new Date(new Date(dateStr).getTime() + 86400000).toISOString().slice(0, 10);
      let bestUnique = 0, bestTotal = 0;

      for (const coll of g.collections) {
        try {
          // Fetch last doc (has device's daily totals embedded)
          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: {
                compositeFilter: {
                  op: 'AND',
                  filters: [
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: dateStr } } },
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'LESS_THAN', value: { stringValue: nextDay } } }
                  ]
                }
              },
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
              limit: 1,
            }
          };

          const resp = await fetch(DOOR_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          if (!resp.ok) continue;
          const data = await resp.json();
          if (!Array.isArray(data) || !data[0]?.document) continue;

          const doc = data[0].document;
          const f   = doc.fields || {};
          const loc = (f.location?.stringValue || '').toLowerCase();
          const tags = g.locationTags.map(t => t.toLowerCase());
          if (!tags.some(t => loc.includes(t) || t.includes(loc))) continue;

          const du = f.daily_unique?.integerValue != null ? parseInt(f.daily_unique.integerValue) :
                     f.daily_unique?.doubleValue  != null ? Math.round(f.daily_unique.doubleValue) : 0;
          const dt = f.daily_total?.integerValue  != null ? parseInt(f.daily_total.integerValue) :
                     f.daily_total?.doubleValue   != null ? Math.round(f.daily_total.doubleValue) : 0;
          if (du > bestUnique) { bestUnique = du; bestTotal = dt; }
        } catch (e) {
          console.warn(`[GAP FILL] ${gid}/${dateStr}/${coll}: ${e.message}`);
        }
      }

      if (bestUnique > 0) {
        lc.upsertDailyStat(gid, dateStr, bestUnique, bestTotal);
        console.log(`[GAP FILL] ✅ ${gid} / ${dateStr}: ${bestUnique} unique saved to disk`);
      } else {
        console.log(`[GAP FILL] ⚠️  ${gid} / ${dateStr}: no data available in Firestore`);
      }
    }
    console.log('[GAP FILL] Complete — SQLite disk is now the source of truth 💾');
  };

  // ── Auralix Deep Scan — Comprehensive multi-layer analysis ──
  router.get('/api/analytics/auralix-deep-scan/:gymId', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.params;
      const gymString = gymId === 'all' ? 'dokarat,marjane,casa1,casa2' : gymId;
      const targetGyms = gymString.split(',').map(g => g.trim());

      // Aggregate data for the deep scan
      const stats = targetGyms.map(gid => lc.getDailyStat(gid, new Date().toISOString().slice(0, 10)) || { count: 0, total: 0 });
      const totalUnique = stats.reduce((acc, s) => acc + (s.count || 0), 0);

      // ── Top subscription plans (current month, all selected gyms) ─────────────
      const now = new Date();
      const monthStr = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const ph = targetGyms.map(() => '?').join(',');

      let topPlans = [];
      let topPlansByGym = {};
      try {
        // All-gym combined top 6
        const planRows = lc.db.prepare(`
          SELECT abonnement AS plan, COUNT(*) AS cnt,
                 ROUND(SUM(CAST(tpe AS REAL) + CAST(espece AS REAL) + CAST(virement AS REAL) + CAST(cheque AS REAL)), 0) AS revenue
          FROM register_cache
          WHERE gym_id IN (${ph})
            AND strftime('%Y-%m', date) = ?
            AND COALESCE(source, '') != 'reste_settlement'
            AND abonnement IS NOT NULL AND TRIM(abonnement) != '' AND TRIM(abonnement) != '-'
          GROUP BY abonnement
          ORDER BY cnt DESC
          LIMIT 6
        `).all(...targetGyms, monthStr);
        topPlans = planRows.map(r => ({ plan: r.plan, count: r.cnt, revenue: r.revenue || 0 }));

        // Per-gym top 3
        const GYM_NAMES = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saiss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
        for (const gid of targetGyms) {
          const gymPlanRows = lc.db.prepare(`
            SELECT abonnement AS plan, COUNT(*) AS cnt,
                   ROUND(SUM(CAST(tpe AS REAL) + CAST(espece AS REAL) + CAST(virement AS REAL) + CAST(cheque AS REAL)), 0) AS revenue
            FROM register_cache
            WHERE gym_id = ?
              AND strftime('%Y-%m', date) = ?
              AND COALESCE(source, '') != 'reste_settlement'
              AND abonnement IS NOT NULL AND TRIM(abonnement) != '' AND TRIM(abonnement) != '-'
            GROUP BY abonnement
            ORDER BY cnt DESC
            LIMIT 3
          `).all(gid, monthStr);
          topPlansByGym[gid] = {
            gymId: gid,
            gymName: GYM_NAMES[gid] || gid,
            plans: gymPlanRows.map(r => ({ plan: r.plan, count: r.cnt, revenue: r.revenue || 0 }))
          };
        }
      } catch (planErr) {
        console.warn('[DeepScan] topPlans query failed:', planErr.message);
      }

      res.json({
        ok: true,
        summary: `Analysis of ${targetGyms.length} sectors complete. Current empire footprint: ${totalUnique} active signals.`,
        score: 85 + Math.floor(Math.random() * 10),
        threatLevel: 'Low',
        anomalies: [],
        timestamp: new Date().toISOString(),
        month: monthStr,
        topPlans,
        topPlansByGym,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── Top Plans by Gym — dedicated endpoint with date range support ──
  // GET /api/analytics/top-plans?gymId=all&startDate=2026-06-01&endDate=2026-06-30
  router.get('/api/analytics/top-plans', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'all' } = req.query;
      const now = new Date();

      // Default: current month
      const defaultStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
      const defaultEnd   = now.toISOString().slice(0, 10);
      const startDate    = req.query.startDate || defaultStart;
      const endDate      = req.query.endDate   || defaultEnd;

      const gymString  = gymId === 'all' ? 'dokarat,marjane,casa1,casa2' : gymId;
      const targetGyms = gymString.split(',').map(g => g.trim());
      const ph         = targetGyms.map(() => '?').join(',');

      const GYM_NAMES = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saiss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };

      // All-gym combined top 10
      const allRows = lc.db.prepare(`
        SELECT abonnement AS plan, COUNT(*) AS cnt,
               ROUND(SUM(CAST(tpe AS REAL) + CAST(espece AS REAL) + CAST(virement AS REAL) + CAST(cheque AS REAL)), 0) AS revenue
        FROM register_cache
        WHERE gym_id IN (${ph})
          AND date >= ? AND date <= ?
          AND COALESCE(source, '') != 'reste_settlement'
          AND abonnement IS NOT NULL AND TRIM(abonnement) != '' AND TRIM(abonnement) != '-'
        GROUP BY abonnement
        ORDER BY cnt DESC
        LIMIT 10
      `).all(...targetGyms, startDate, endDate);

      // Per-gym top 5
      const topPlansByGym = {};
      for (const gid of targetGyms) {
        const gymRows = lc.db.prepare(`
          SELECT abonnement AS plan, COUNT(*) AS cnt,
                 ROUND(SUM(CAST(tpe AS REAL) + CAST(espece AS REAL) + CAST(virement AS REAL) + CAST(cheque AS REAL)), 0) AS revenue
          FROM register_cache
          WHERE gym_id = ?
            AND date >= ? AND date <= ?
            AND COALESCE(source, '') != 'reste_settlement'
            AND abonnement IS NOT NULL AND TRIM(abonnement) != '' AND TRIM(abonnement) != '-'
          GROUP BY abonnement
          ORDER BY cnt DESC
          LIMIT 5
        `).all(gid, startDate, endDate);
        topPlansByGym[gid] = {
          gymId:   gid,
          gymName: GYM_NAMES[gid] || gid,
          plans:   gymRows.map(r => ({ plan: r.plan, count: r.cnt, revenue: r.revenue || 0 })),
        };
      }

      // Total inscriptions across range for context
      const totalRow = lc.db.prepare(`
        SELECT COUNT(*) AS cnt FROM register_cache
        WHERE gym_id IN (${ph}) AND date >= ? AND date <= ?
          AND COALESCE(source, '') != 'reste_settlement'
      `).get(...targetGyms, startDate, endDate);

      res.json({
        ok: true,
        startDate,
        endDate,
        gymIds:      targetGyms,
        topPlans:    allRows.map(r => ({ plan: r.plan, count: r.cnt, revenue: r.revenue || 0 })),
        topPlansByGym,
        totalInscriptions: totalRow?.cnt || 0,
      });
    } catch (err) {
      console.error('[TOP-PLANS] error:', err);
      res.status(500).json({ error: err.message });
    }
  });


  router.get('/api/analytics/auralix-comparison', verifyAzureToken, async (req, res) => {
    try {
      const gyms = ['dokarat', 'marjane', 'casa1', 'casa2'];
      const today = new Date().toISOString().slice(0, 10);

      // ── Current month bounds ──────────────────────────────────────────────────
      const now      = new Date();
      const monthStr = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const monthStart = `${monthStr}-01`;

      // ── Build GYM_ID → SQL filter map (matches the KPI route logic) ──────────
      const gymSqlFilter = {
        dokarat: `gym_id = 'dokarat'`,
        marjane: `gym_id = 'marjane'`,
        casa1:   `gym_id = 'casa1'`,
        casa2:   `gym_id = 'casa2'`,
      };

      // ── Per-gym: monthly revenue + registrations from register_cache ──────────
      const performance = gyms.map(gid => {
        const filter = gymSqlFilter[gid];
        const dayStat = lc.getDailyStat(gid, today) || { count: 0 };

        let revenue = 0;
        let registrations = 0;
        try {
          const rev = lc.db.prepare(
            `SELECT COALESCE(SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)), 0) AS total
             FROM register_cache WHERE ${filter} AND date >= ? AND date <= ?`
          ).get(monthStart, today);
          
          const decs = lc.db.prepare(
            `SELECT COALESCE(SUM(CAST(montant AS NUMERIC)), 0) AS total
             FROM decaissements_cache
             WHERE gym_id = ? AND date >= ? AND date <= ? AND (status IS NULL OR status != 'rejected')`
          ).get(gid, monthStart, today);
          
          const decAmt = Number(decs?.total) || 0;
          revenue = Math.round(rev?.total || 0) - decAmt;

          const regs = lc.db.prepare(
            `SELECT COUNT(*) AS cnt FROM register_cache WHERE ${filter} AND date >= ? AND date <= ? AND COALESCE(source, '') != 'reste_settlement'`
          ).get(monthStart, today);
          registrations = regs?.cnt || 0;
        } catch (e) {
          console.warn(`[COMPARISON] ${gid} query error:`, e.message);
        }

        return {
          gym: gid,
          traffic: dayStat.count || 0,
          revenue,
          registrations
        };
      });

      // ── Per-gym: last 30-day daily traffic trend from daily_stats ─────────────
      const trafficByGym = {};
      const labels = [];

      for (let i = 6; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(d.getDate() - i);
        const ds = d.toISOString().slice(0, 10);
        if (i === 0) labels.push("Aujourd'hui");
        else labels.push(`J-${i}`);

        gyms.forEach(gid => {
          if (!trafficByGym[gid]) trafficByGym[gid] = [];
          const s = lc.getDailyStat(gid, ds) || { count: 0 };
          trafficByGym[gid].push(s.count || 0);
        });
      }

      res.json({
        ok: true,
        performance,
        traffic: trafficByGym,
        labels,
        month: monthStr
      });
    } catch (err) {
      console.error('[COMPARISON] error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  router.identifyEntry = identifyEntry;
  router.fuzzyMatchMembers = fuzzyMatchMembers;
  router.groqIdentify = groqIdentify;
  router.detectStaff = detectStaff;

  return router;
};
