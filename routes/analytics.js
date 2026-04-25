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

  const GYM_DOOR_MAP = {
    dokarat: { collections: ['mega_fit_logs'],                       locationTags: ['dokkarat'] },
    marjane: { collections: ['saiss entrees logs', 'mega_fit_logs'], locationTags: ['saiss', 'marjane'] },
    casa1:   { collections: ['mega_fit_logs'],                       locationTags: ['casa anfa'] },
    casa2:   { collections: ['mega_fit_logs'],                       locationTags: ['lady anfa'] },
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
      let merged = [];
      targetGymIds.forEach(gid => {
        lc.getEntries(gid, today, limitCount).forEach(e => merged.push({
          docId: e.id, name: e.name, gymId: gid,
          displayTime: (e.timestamp || '').slice(11, 16),
          timestamp: e.timestamp, status: e.status,
          method: e.method, isFace: e.is_face === 1,
        }));
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
        const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : [gymId];
        let totalCount = 0, totalRaw = 0;
        for (const gid of gymIds) {
          const cached = lc.getDailyStat(gid, today);
          if (cached && cached.count > 0) { totalCount += cached.count; totalRaw += cached.raw_count; }
          else { totalCount += lc.getUniqueEntryCount(gid, today); totalRaw += lc.getEntryCount(gid, today); }
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
      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : gymId.split(',');
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

      const ts = (d) => admin.firestore.Timestamp.fromDate(d);
      const tsToday = ts(todayStart), tsWeek = ts(weekStart), tsMonth = ts(monthStart), tsYear = ts(yearStart);

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

      const gymIds = gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : gymId.split(',');
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

      // ?????? Count SQLite entries this month to decide if we need Firestore ??????
      const countCachedEntries = (fromDate) => {
        let count = 0;
        const cursor = new Date(fromDate);
        while (cursor <= now) {
          const dateStr = toLocalDateStr(cursor);
          for (const gid of gymIds) count += lc.getRegister(gid, dateStr).length;
          cursor.setDate(cursor.getDate() + 1);
        }
        return count;
      };

      // ?????? Firestore fallback for historical months not yet in SQLite ??????
      const fetchFirestoreRegisterIncome = async (fromTs) => {
        const start = new Date(fromTs.toMillis());
        const dayCount = Math.ceil((now - start) / (1000 * 60 * 60 * 24)) + 1;
        const docRefs = [];
        const decRefs = [];
        for (let i = 0; i < dayCount; i++) {
          const d = new Date(start); d.setDate(start.getDate() + i); if (d > now) break;
          const dateStr = toLocalDateStr(d);
          gymIds.forEach(gid => {
            docRefs.push(db.collection('megafit_daily_register').doc(`${gid}_${dateStr}`).collection('entries'));
            decRefs.push(db.collection('megafit_daily_register').doc(`${gid}_${dateStr}`).collection('decaissements'));
          });
        }
        const snaps = await Promise.all(docRefs.map(r => r.get()));
        const decSnaps = await Promise.all(decRefs.map(r => r.get()));
        
        let total = 0, espece = 0, tpe = 0, virement = 0, cheque = 0;
        snaps.forEach(snap => snap.forEach(doc => {
          const e = doc.data();
          const e_esp = Number(e.espece) || 0;
          const e_tpe = Number(e.tpe) || 0;
          const e_vir = Number(e.virement) || 0;
          const e_che = Number(e.cheque) || 0;
          espece += e_esp; tpe += e_tpe; virement += e_vir; cheque += e_che;
          total += e_esp + e_tpe + e_vir + e_che;
        }));
        decSnaps.forEach(snap => snap.forEach(doc => {
          const amt = Number(doc.data().montant) || 0;
          espece -= amt;
          total -= amt;
        }));
        return { total, espece, tpe, virement, cheque };
      };

      const monthCachedCount = countCachedEntries(monthStart);
      let incomeDay, incomeWeek, incomeMonth, incomeYear;

      if (monthCachedCount >= 3) {
        // SQLite has data ??? use it (fast, no quota cost)
        console.log(`??? [KPI] SQLite: ${monthCachedCount} entries for ${gymId} ??? reading prix from local cache`);
        incomeDay   = getRevenueAndBreakdown(todayStart);
        incomeWeek  = getRevenueAndBreakdown(weekStart);
        incomeMonth = getRevenueAndBreakdown(monthStart);
        incomeYear  = getRevenueAndBreakdown(yearStart);
      } else {
        // Fallback to Firestore
        console.log(`???? [KPI] SQLite sparse (${monthCachedCount} entries) for ${gymId} ??? falling back to Firestore`);
        [incomeDay, incomeWeek, incomeMonth, incomeYear] = await Promise.all([
          fetchFirestoreRegisterIncome(tsToday),
          fetchFirestoreRegisterIncome(tsWeek),
          fetchFirestoreRegisterIncome(tsMonth),
          fetchFirestoreRegisterIncome(tsYear),
        ]);
      }

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

  // ?????? POST /api/analytics/log-entry ????????????????????????????????????????????????????????????????????????????????????????????????
  router.post('/api/analytics/log-entry', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, userId } = req.body;
      if (!gymId || !userId) return res.status(400).json({ error: 'gymId and userId required' });
      const now = new Date();
      const todayStr = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`;
      const docRef     = db.collection('gym_daily_stats').doc(`${gymId}_${todayStr}`);
      const visitorRef = docRef.collection('visitors').doc(userId);

      await db.runTransaction(async (t) => {
        const doc = await t.get(docRef);
        const vis = await t.get(visitorRef);
        if (vis.exists && Date.now() - vis.data().lastScannedAt.toDate().getTime() < 600000) { console.log(`??????? Dedup: ${userId} at ${gymId}`); return; }
        if (!doc.exists) { t.set(docRef, { gym_id: gymId, date: todayStr, count: 1, lastSyncedAt: admin.firestore.FieldValue.serverTimestamp() }); }
        else { t.update(docRef, { count: (doc.data().count || 0) + 1, lastSyncedAt: admin.firestore.FieldValue.serverTimestamp() }); }
        t.set(visitorRef, { userId, lastScannedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      });
      res.json({ ok: true });
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
      const GYM_NAMES = { all: 'ALL EMPIRE (Dokarat + Marjane + Casa Anfa + Lady Anfa)', dokarat: 'Dokarat (F??s)', marjane: 'Marjane Saiss (F??s)', casa1: 'Casa Anfa (Casablanca)', casa2: 'Lady Anfa (Casablanca)' };
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

      // ?????? Course & Reservation Context ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
      let courseContext = '';
      try {
        const cSnap = await db.collection('courses').get();
        if (!cSnap.empty) {
           courseContext = `\n--- CURRENT SCHEDULE & RESERVATIONS ---\n`;
           cSnap.docs.forEach(doc => {
              const d = doc.data();
              // Summarize course info compactly
              courseContext += `- ${d.title} (${d.coach}) | Days: ${(d.days||[]).join(',')} | Time: ${d.time} | Booked: ${d.reserved||0}/${d.capacity}\n`;
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


  // ── pollDoorEntries — server-side background task, called every 60s ──────────
  // ✅ EFFICIENT: Only reads the LAST 1 document per gym collection.
  // The device embeds daily_unique + daily_total in every scan, so the
  // last scan of the day always has the current running total.
  // Cost: 1 read per gym per minute (not 200). Zero counting needed.
  router.pollDoorEntries = async function pollDoorEntries() {
    const today = getMoroccanDateStr();
    const nextDay = new Date(new Date(today).getTime() + 86400000).toISOString().slice(0, 10);

    for (const [gid, g] of Object.entries(GYM_DOOR_MAP)) {
      try {
        let bestUnique = 0;
        let bestTotal  = 0;

        for (const coll of g.collections) {
          // Fetch ONLY the last 1 document for today
          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: {
                compositeFilter: {
                  op: 'AND',
                  filters: [
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: today } } },
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'LESS_THAN', value: { stringValue: nextDay } } }
                  ]
                }
              },
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
              limit: 1,
            }
          };

          const resp = await fetch(DOOR_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          const data = await resp.json();
          if (!Array.isArray(data) || !data[0]?.document) continue;

          const f   = data[0].document.fields || {};
          const loc = (f.location?.stringValue || '').toLowerCase();
          const tags = g.locationTags.map(t => t.toLowerCase());

          // Verify this doc belongs to this gym
          if (!tags.some(t => loc.includes(t) || t.includes(loc))) continue;

          // Read the device-embedded running totals directly
          const du = f.daily_unique?.integerValue != null ? parseInt(f.daily_unique.integerValue) :
                     f.daily_unique?.doubleValue  != null ? Math.round(f.daily_unique.doubleValue) : 0;
          const dt = f.daily_total?.integerValue  != null ? parseInt(f.daily_total.integerValue) :
                     f.daily_total?.doubleValue   != null ? Math.round(f.daily_total.doubleValue) : 0;

          if (du > bestUnique) { bestUnique = du; bestTotal = dt; }
        }

        // Save to SQLite daily_stats — this is what the chart reads
        if (bestUnique > 0) {
          const prev = lc.getDailyStats(gid, 1)[0]?.count || 0;
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

  return router;
};