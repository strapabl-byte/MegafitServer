'use strict';
// routes/analytics.js ??? Daily stats, KPIs, live door entries, entry logging

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function analyticsRouter({ db, admin, lc, apiCache, isQuotaExceeded, getCachedOrFetch, syncGymCounts }) {
  const router = Router();

  function getMoroccanDateStr() {
    const d = new Date();
    d.setTime(d.getTime() + 60 * 60 * 1000);
    return d.toISOString().slice(0, 10);
  }

  // Door-device gyms — only gyms with actual biometric terminals connected
  // casa1/casa2 have no door device yet → excluded from door polling & gap fill
  const GYM_DOOR_MAP = {
    dokarat: { collections: ['mega_fit_logs'],       locationTags: ['dokkarat'] },
    marjane: { collections: ['saiss entrees logs'], locationTags: ['saiss', 'marjane'] },
  };

  const DOOR_URL = `https://firestore.googleapis.com/v1/projects/${process.env.DOOR_PROJECT_ID || 'megadoor-b3ccb'}/databases/(default)/documents:runQuery?key=${process.env.DOOR_FIREBASE_API_KEY || ''}`;

  // ?????? GET /api/analytics/megaeye-registrations ??????????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/analytics/megaeye-registrations', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, timeFilter } = req.query; // 'day' or 'week'
      const rows = lc.getPending(gymId, timeFilter || 'day');
      res.json(rows);
    } catch (err) {
      console.error('Megaeye Registrations Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch megaeye registrations' });
    }
  });

  // ?????? GET /api/live-entries ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/live-entries', verifyAzureToken, (req, res) => {
    try {
      const { gymId, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      const limitCount = Math.min(parseInt(limitParam) || 50, 200);
      const today = getMoroccanDateStr();
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

      let merged = [];
      targetGymIds.forEach(gid => {
        lc.getEntries(gid, today, limitCount).forEach(e => {
          let member = null;
          let matchMethod = 'none';

          // ── 1. Exact match by ZKTeco user_id (most reliable, Doukkarate new format) ──
          if (e.user_id) {
            member = memberByUserId.get(String(e.user_id)) || null;
            if (member) matchMethod = 'user_id';
          }

          // ── 2. Fallback: exact name match ─────────────────────────────────────────
          if (!member) {
            // Use the clean display name (already stripped of [ID] prefix by pollDoorEntries)
            const entryNorm = normalize(e.name);
            member = memberByName.get(entryNorm) || null;
            if (member) matchMethod = 'name_exact';

            // ── 3. Partial name match (legacy names, single-word entries) ───────────
            if (!member && entryNorm.length > 3) {
              const entryFirst = entryNorm.split(' ')[0];
              for (const [mName, mData] of memberByName.entries()) {
                if (mName.includes(entryNorm) || (entryFirst.length > 3 && mName.startsWith(entryFirst))) {
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

          merged.push({
            docId:        e.id,
            name:         e.name,
            userId:       e.user_id || null,      // ZKTeco machine ID
            gymId:        gid,
            displayTime:  (e.timestamp || '').slice(11, 16),
            timestamp:    e.timestamp,
            status:       e.status,
            method:       e.method,
            isFace:       e.is_face === 1,
            isKnown,
            memberStatus,
            matchMethod,  // how the cross-ref was resolved (user_id / name_exact / name_partial / none)
            expiresOn:    member ? member.expiresOn : null,
            userTodayCount: lc.db.prepare('SELECT COUNT(*) as count FROM entries WHERE gym_id=? AND name=? AND date=?').get(gid, e.name, today)?.count || 1
          });
        });
      });

      merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      res.json({ ok: true, gymId, count: merged.length, entries: merged.slice(0, limitCount) });
    } catch (err) {
      console.error('Live Entries Error:', err);
      res.status(500).json({ error: 'Failed to fetch live entries' });
    }
  });


  // GET /api/live-count
  router.get('/api/live-count', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      const today = getMoroccanDateStr();
      const cacheKey = `live_count_${gymId}`;
      const result = await getCachedOrFetch(apiCache.general, cacheKey, 30000, async () => {
        const gymIds = gymId === 'all' ? ['marjane', 'dokarat'] : [gymId];
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

  // ?????? GET /api/analytics/daily-stats/:gymId ????????????????????????????????????????????????????????????????????????
  router.get('/api/analytics/daily-stats/:gymId', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.params;
      const includeToday = req.query.includeToday === 'true';
      const gymIds = gymId === 'all' ? ['marjane', 'dokarat'] : gymId.split(',');
      const today = getMoroccanDateStr();

      // Build date range:
      // - includeToday=true  ??? 30 days ending AT today (home page chart, shows live)
      // - includeToday=false ??? 30 days ending at YESTERDAY (Revenue Chronology, no mid-day drop)
      const days = 30;
      const offset = includeToday ? 0 : 1; // 0 = include today, 1 = stop at yesterday
      const dateStrs = Array.from({ length: days }, (_, i) =>
        new Date(Date.now() + 3600000 - (days - 1 - i + offset) * 86400000).toISOString().slice(0, 10)
      );

      const map = {};
      dateStrs.forEach(d => map[d] = { count: 0, rawCount: 0, revenue: 0, revPerGym: {} });

      for (const gid of gymIds) {
        lc.getDailyStats(gid, 31).forEach(s => {
          if (map[s.date]) {
            map[s.date].count    += s.count    || 0;
            map[s.date].rawCount += s.rawCount || 0;
          }
        });
          // daily_stats for today is updated every 60s by pollDoorEntries — already included above
          // Fallback only if daily_stats has no data for today yet
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

      res.json(dateStrs.map(date => ({ gym_id: gymId, date, count: map[date].count, rawCount: map[date].rawCount, revenue: map[date].revenue, revPerGym: map[date].revPerGym })));
    } catch (err) {
      console.error('Daily Stats Error:', err);
      res.status(500).json({ error: 'Failed to fetch analytics' });
    }
  });

  // ?????? GET /api/analytics/kpis/:gymId ???????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/analytics/kpis/:gymId', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.params;
      const cached = apiCache.kpis[gymId];
      if (cached && Date.now() - cached.ts < 30 * 1000) return res.json(cached.data);

      const now = new Date();
      const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const dayOfWeek = now.getDay();
      const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() + (dayOfWeek === 0 ? -6 : 1 - dayOfWeek));
      weekStart.setHours(0, 0, 0, 0);
      const monthStart  = new Date(now.getFullYear(), now.getMonth(), 1);
      const yearStart   = new Date(now.getFullYear(), 0, 1);

      // 🔒 DISK-ONLY: All KPI data comes from SQLite register_cache. No Firebase reads.

      // ?????? New members count from register (source of truth, same as Register page) ??????
      const countRegisterInRange = (fromDate) => {
        let count = 0;
        const cursor = new Date(fromDate);
        while (cursor <= now) {
          const dateStr = toLocalDateStr(cursor);
          for (const gid of gymIds) count += lc.getRegister(gid, dateStr).length;
          cursor.setDate(cursor.getDate() + 1);
        }
        return count;
      };

      const gymIds = gymId === 'all' ? ['dokarat', 'marjane'] : gymId.split(',');
      const toLocalDateStr = (d) => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;

      // ?????? Revenue from SQLite register cache ??? sum ALL payment columns ??????
      const getRevenueAndBreakdown = (fromDate) => {
        let total = 0, espece = 0, tpe = 0, virement = 0, cheque = 0;
        const cursor = new Date(fromDate);
        while (cursor <= now) {
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
            const decs = lc.getDecaissements(gid, dateStr);
            if (decs) {
              decs.forEach(dec => {
                const amt = Number(dec.montant) || 0;
                espece -= amt;
                total -= amt;
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
      console.log(`💾 [KPI] SQLite: ${monthCachedCount} entries for ${gymId} — reading from disk only`);
      const incomeDay   = getRevenueAndBreakdown(todayStart);
      const incomeWeek  = getRevenueAndBreakdown(weekStart);
      const incomeMonth = getRevenueAndBreakdown(monthStart);
      const incomeYear  = getRevenueAndBreakdown(yearStart);

      const kpis = {
        newMembers: { day: countRegisterInRange(todayStart), week: countRegisterInRange(weekStart), month: countRegisterInRange(monthStart), year: countRegisterInRange(yearStart) },
        income:     { day: incomeDay.total, week: incomeWeek.total, month: incomeMonth.total, year: incomeYear.total },
        paymentMethods: { espece: incomeMonth.espece, tpe: incomeMonth.tpe, virement: incomeMonth.virement, cheque: incomeMonth.cheque }
      };

      apiCache.kpis[gymId] = { data: kpis, ts: Date.now() };
      console.log(`???? [KPI] ${gymId}: income day=${incomeDay.total} | week=${incomeWeek.total} | month=${incomeMonth.total} | year=${incomeYear.total} DH`);
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
      const expected = process.env.INJECT_SECRET || 'megafit-seed-2026';
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

  // ?????? POST /api/analytics/megaeye-chat ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
  // Interactive Groq chat: accepts a user question + context, returns AI answer
  router.post('/api/analytics/megaeye-chat', verifyAzureToken, requireAdmin, async (req, res) => {
    const { question, sector, kpis, dailyStats, liveEntries } = req.body;
    if (!question) return res.status(400).json({ error: 'question required' });

    const GROQ_KEY          = process.env.GROQ_API_KEY;
    const GROQ_KEY_FALLBACK = process.env.GROQ_API_KEY_FALLBACK;

    if (!GROQ_KEY && !GROQ_KEY_FALLBACK) {
      return res.json({ answer: '?????? No GROQ_API_KEY configured on server.' });
    }

    // Helper: call Groq ??? models confirmed active via /openai/v1/models (April 2026)
    const GROQ_MODEL          = 'llama-3.3-70b-versatile'; // primary
    const GROQ_MODEL_FALLBACK = 'llama-3.1-8b-instant';    // fallback
    const callGroq = async (key, messages, model = GROQ_MODEL) => {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages, max_tokens: 1200, temperature: 0.5 })
      });
      if (!r.ok) {
        const errBody = await r.text();
        console.error(`[Groq] HTTP ${r.status}:`, errBody.slice(0, 300));
        throw new Error(`Groq HTTP ${r.status}`);
      }
      return r.json();
    };

    try {
      // ?????? Gym name mapping ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
      const GYM_NAMES = { all: 'ALL EMPIRE (Dokarat + Marjane)', dokarat: 'Dokarat (Fès)', marjane: 'Marjane Saiss (Fès)' };
      const sectorName = GYM_NAMES[sector] || sector || 'ALL EMPIRE';

      // ?????? KPI context ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
      const kpiContext = kpis ? [
        `GYM / SECTOR: ${sectorName}`,
        `Revenue  ??? Today: ${(kpis?.income?.day||0).toLocaleString()} DH | This week: ${(kpis?.income?.week||0).toLocaleString()} DH | This month: ${(kpis?.income?.month||0).toLocaleString()} DH | This year: ${(kpis?.income?.year||0).toLocaleString()} DH`,
        `New memberships ??? Today: ${kpis?.newMembers?.day||0} | This week: ${kpis?.newMembers?.week||0} | This month: ${kpis?.newMembers?.month||0}`,
        `Total active members: ${kpis?.totalActive || 'N/A'}`,
      ].join('\n') : `GYM / SECTOR: ${sectorName}\nNo KPI data available.`;

      // ?????? 30-day door traffic from SQLite ???????????????????????????????????????????????????????????????????????????????????????????????????????????????
      let trafficContext = '';
      if (Array.isArray(dailyStats) && dailyStats.length > 0) {
        const total30 = dailyStats.reduce((s, d) => s + (d.count || 0), 0);
        const avg30   = Math.round(total30 / dailyStats.length);
        const maxDay  = dailyStats.reduce((m, d) => (d.count||0) > (m.count||0) ? d : m, dailyStats[0]);
        const today   = dailyStats[dailyStats.length - 1];
        const last7   = dailyStats.slice(-7).reduce((s, d) => s + (d.count||0), 0);
        trafficContext = [
          `\n--- 30-DAY DOOR TRAFFIC (${sectorName}) ---`,
          `Today (${today?.date}): ${today?.count||0} check-ins`,
          `Last 7 days: ${last7} check-ins | 30-day avg: ${avg30}/day | 30-day total: ${total30}`,
          `Busiest day: ${maxDay?.date} with ${maxDay?.count} check-ins`,
          `Daily (last 10 days): ${dailyStats.slice(-10).map(d=>`${d.date.slice(5)}:${d.count||0}`).join(' | ')}`,
        ].join('\n');
      }
      // ?????? Live door entries ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
      let liveContext = '';
      if (Array.isArray(liveEntries) && liveEntries.length > 0) {
        liveContext = `\n--- LIVE ENTRIES TODAY (${sectorName}) ---\n` +
          liveEntries.map(e => `  ${e.name||'?'} @ ${e.time ? new Date(e.time).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}) : '??:??'} (${e.source||'scan'})`).join('\n');
      }

      // 🔒 DISK-ONLY: Course context read from SQLite courses_cache (no Firebase).
      let courseContext = '';
      try {
        const courseRows = lc.db ? lc.db.prepare(
          `SELECT title, coach, days, time, reserved, capacity FROM courses_cache LIMIT 50`
        ).all() : [];
        if (courseRows.length > 0) {
          courseContext = `\n--- CURRENT SCHEDULE & RESERVATIONS ---\n`;
          courseRows.forEach(d => {
            let daysList = '';
            try { daysList = (JSON.parse(d.days || '[]')).join(','); } catch { daysList = d.days || ''; }
            courseContext += `- ${d.title || '?'} (${d.coach || '?'}) | Days: ${daysList} | Time: ${d.time || '?'} | Booked: ${d.reserved||0}/${d.capacity||'?'}\n`;
          });
        }
      } catch (err) {
        console.error("Megaeye course context error:", err);
      }

      // ?????? Subscriptions Context ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
      let subsContext = '';
      try {
         const { DEFAULT_SUBSCRIPTION_GROUPS } = require('./config');
         if (DEFAULT_SUBSCRIPTION_GROUPS) {
            subsContext = `=== AVAILABLE SUBSCRIPTION FORMULAS (DHS) ===\n` + 
              DEFAULT_SUBSCRIPTION_GROUPS.map(g => `TYPE: ${g.label}\n` + g.options.map(o => ` - ${o.name}: ${o.price > 0 ? o.price + ' DHS' : 'Tarif Inclus/Variable'}`).join('\n')).join('\n');
         }
      } catch (e) {
         console.error("Megaeye subs context error:", e);
      }

      const fullContext = [kpiContext, trafficContext, liveContext, courseContext, subsContext].filter(Boolean).join('\n\n');

      const messages = [
        {
          role: 'system',
          content: `You are MEGAEYE, an elite, hyper-intelligent tactical AI assistant for the MegaFit gym empire.

IMPORTANT RULES FOR YOUR ANALYSIS:
1. DELIVER ULTRA-CONDENSED, HIGH-DENSITY TACTICAL INTEL. Do not write long narrative paragraphs. Use extremely concise military/corporate logic. Get straight to the point.
2. Directly answer the feasibility of goals mathematically. If we need exactly 58 members, say "TARGET: 58 CONVERSIONS REQUIRED". Do not over-explain basic math.
3. Provide ONLY actionable, high-leverage operational directives. No generic "Marketing" fluff. Give exact mathematical targets and leverage specific pricing tiers.
4. Format your output sharply using bullet points. Never exceed significantly long word counts. Be brutal, sharp, and accurate.
5. Answer ONLY in French, using professional, high-impact tactical corporate terminology.
6. End response with [+] if confident or [-] if uncertain.

=== CURRENT DATA (${sectorName}) ===
${fullContext}`
        },
        { role: 'user', content: question }
      ];

      // Try primary key, fall back to secondary on any error
      let data;
      try {
        data = await callGroq(GROQ_KEY, messages, GROQ_MODEL);
      } catch (primaryErr) {
        console.warn(`[Groq] Primary key/model failed (${primaryErr.message}), trying fallback...`);
        const fallbackKey = GROQ_KEY_FALLBACK || GROQ_KEY;
        data = await callGroq(fallbackKey, messages, GROQ_MODEL_FALLBACK);
      }

      let raw = data?.choices?.[0]?.message?.content || 'No response from Groq.';
      // Parse and strip the sentiment tag
      let sentiment = 'positive';
      if (raw.endsWith('[-]')) { sentiment = 'negative'; raw = raw.slice(0, -3).trim(); }
      else if (raw.endsWith('[+]')) { sentiment = 'positive'; raw = raw.slice(0, -3).trim(); }
      res.json({ answer: raw, sentiment });
    } catch (err) {
      console.error('Groq chat error:', err);
      res.status(500).json({ error: 'Groq service unavailable', answer: '?????? Neural core offline.' });
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
          const prev = lc.getDailyStat(gid, today)?.count || 0;
          lc.upsertDailyStat(gid, today, bestUnique, bestTotal);
          if (bestUnique !== prev) {
            console.log(`[DOOR POLL] ${gid}: ${bestUnique} unique / ${bestTotal} total today`);
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

  return router;
};
