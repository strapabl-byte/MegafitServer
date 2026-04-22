'use strict';
// routes/analytics.js — Daily stats, KPIs, live door entries, entry logging

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

  // ── GET /api/analytics/megaeye-registrations ──────────────────────────────
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

  // ── GET /api/live-entries ───────────────────────────────────────
  router.get('/api/live-entries', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      const limitCount = Math.min(parseInt(limitParam) || 50, 200);
      const today = getMoroccanDateStr();
      const targetGymIds = gymId === 'all' ? Object.keys(GYM_DOOR_MAP) : [gymId];

      await Promise.all(targetGymIds.map(async (gid) => {
        const g = GYM_DOOR_MAP[gid];
        if (!g) return;
        const FETCH_MIN_GAP_MS = 12000;
        const lastSyncKey      = `liveEntries_sync_${gid}`;
        const lastSyncTime     = parseInt(lc.getMeta(lastSyncKey) || '0');
        const existingEntries  = lc.getEntries(gid, today, 100);
        const lastTimestamp    = existingEntries.length > 0 ? existingEntries.reduce((max, e) => e.timestamp > max ? e.timestamp : max, '') : null;

        if (!lastTimestamp || Date.now() - lastSyncTime >= FETCH_MIN_GAP_MS) {
          try {
            const newEntries = [];
            for (const coll of g.collections) {
              const body = { structuredQuery: { from: [{ collectionId: coll }], where: { fieldFilter: { field: { fieldPath: 'timestamp' }, op: lastTimestamp ? 'GREATER_THAN' : 'GREATER_THAN_OR_EQUAL', value: { stringValue: lastTimestamp || today } } }, orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'ASCENDING' }], limit: 200 } };
              const resp = await fetch(DOOR_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
              const data = await resp.json();
              if (!Array.isArray(data)) continue;
              data.filter(d => d.document).forEach(d => {
                const f  = d.document.fields || {};
                const ts = f.timestamp?.stringValue || '';
                if (!ts.startsWith(today)) return;
                const loc  = (f.location?.stringValue || '').toLowerCase();
                const tags = g.locationTags.map(t => t.toLowerCase());
                if (!tags.some(t => loc.includes(t) || t.includes(loc))) return;
                newEntries.push({ id: d.document.name?.split('/').pop() || ts, gym_id: gid, date: today, timestamp: ts, name: f.name?.stringValue || '', method: f.method?.stringValue || '', status: f.status?.stringValue || 'Entrée', is_face: (f.method?.stringValue || '').toLowerCase().includes('face') ? 1 : 0 });
              });
            }
            if (newEntries.length > 0) lc.upsertEntries(gid, newEntries);
            lc.setMeta(lastSyncKey, String(Date.now()));
          } catch (e) { console.warn(`⚠️ Sync failed for ${gid}: ${e.message}`); }
        }
      }));

      let merged = [];
      targetGymIds.forEach(gid => {
        lc.getEntries(gid, today, limitCount).forEach(e => merged.push({ docId: e.id, name: e.name, gymId: gid, displayTime: (e.timestamp || '').slice(11, 16), timestamp: e.timestamp, status: e.status, method: e.method, isFace: e.is_face === 1 }));
      });
      merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      const final = merged.slice(0, limitCount);
      res.json({ ok: true, gymId, count: final.length, entries: final });
    } catch (err) {
      console.error('Live Entries Error:', err);
      res.status(500).json({ error: 'Failed to fetch live entries' });
    }
  });

  // ── GET /api/live-count ────────────────────────────────────────
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

  // ── GET /api/analytics/daily-stats/:gymId ────────────────────────
  router.get('/api/analytics/daily-stats/:gymId', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.params;
      const includeToday = req.query.includeToday === 'true';
      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : gymId.split(',');
      const today = getMoroccanDateStr();

      // Build date range:
      // - includeToday=true  → 30 days ending AT today (home page chart, shows live)
      // - includeToday=false → 30 days ending at YESTERDAY (Revenue Chronology, no mid-day drop)
      const days = 30;
      const offset = includeToday ? 0 : 1; // 0 = include today, 1 = stop at yesterday
      const dateStrs = Array.from({ length: days }, (_, i) =>
        new Date(Date.now() + 3600000 - (days - 1 - i + offset) * 86400000).toISOString().slice(0, 10)
      );

      const map = {};
      dateStrs.forEach(d => map[d] = { count: 0, rawCount: 0, revenue: 0, revPerGym: {} });

      for (const gid of gymIds) {
        lc.getDailyStats(gid, 31).forEach(s => {
          if (map[s.date] && s.date !== today) {
            map[s.date].count    += s.count    || 0;
            map[s.date].rawCount += s.rawCount || 0;
          }
        });
        // Merge live count for today only when requested
        if (includeToday && map[today] !== undefined) {
          const cached = lc.getDailyStat(gid, today);
          const uniq   = lc.getUniqueEntryCount(gid, today);
          const raw    = lc.getEntryCount(gid, today);
          map[today].count    += cached ? Math.max(cached.count, uniq) : uniq;
          map[today].rawCount += cached ? Math.max(cached.raw_count, raw) : raw;
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

  // ── GET /api/analytics/kpis/:gymId ─────────────────────────────
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

      // ── New members count from register (source of truth, same as Register page) ──
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

      // ── Revenue from SQLite register cache — sum ALL payment columns ──
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

      // ── Count SQLite entries this month to decide if we need Firestore ──
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

      // ── Firestore fallback for historical months not yet in SQLite ──
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
        // SQLite has data — use it (fast, no quota cost)
        console.log(`✅ [KPI] SQLite: ${monthCachedCount} entries for ${gymId} — reading prix from local cache`);
        incomeDay   = getRevenueAndBreakdown(todayStart);
        incomeWeek  = getRevenueAndBreakdown(weekStart);
        incomeMonth = getRevenueAndBreakdown(monthStart);
        incomeYear  = getRevenueAndBreakdown(yearStart);
      } else {
        // Fallback to Firestore
        console.log(`📡 [KPI] SQLite sparse (${monthCachedCount} entries) for ${gymId} — falling back to Firestore`);
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
      console.log(`📊 [KPI] ${gymId}: income day=${incomeDay.total} | week=${incomeWeek.total} | month=${incomeMonth.total} | year=${incomeYear.total} DH`);
      res.json(kpis);
    } catch (err) {
      console.error('KPI Calculation Error:', err);
      res.status(500).json({ error: 'Failed to calculate KPIs' });
    }
  });

  // ── POST /api/admin/sync-stats ──────────────────────────────────
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

  // ── POST /api/analytics/log-entry ────────────────────────────────
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
        if (vis.exists && Date.now() - vis.data().lastScannedAt.toDate().getTime() < 600000) { console.log(`🛡️ Dedup: ${userId} at ${gymId}`); return; }
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

  // ── POST /api/analytics/megaeye-chat ────────────────────────────────────────
  // Interactive Groq chat: accepts a user question + context, returns AI answer
  router.post('/api/analytics/megaeye-chat', verifyAzureToken, requireAdmin, async (req, res) => {
    const { question, sector, kpis, dailyStats, liveEntries } = req.body;
    if (!question) return res.status(400).json({ error: 'question required' });

    const GROQ_KEY          = process.env.GROQ_API_KEY;
    const GROQ_KEY_FALLBACK = process.env.GROQ_API_KEY_FALLBACK;

    if (!GROQ_KEY && !GROQ_KEY_FALLBACK) {
      return res.json({ answer: '⚠️ No GROQ_API_KEY configured on server.' });
    }

    // Helper: call Groq — models confirmed active via /openai/v1/models (April 2026)
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
      // ── Gym name mapping ────────────────────────────────────────────────────
      const GYM_NAMES = { all: 'ALL EMPIRE (Dokarat + Marjane + Casa Anfa + Lady Anfa)', dokarat: 'Dokarat (Fès)', marjane: 'Marjane Saiss (Fès)', casa1: 'Casa Anfa (Casablanca)', casa2: 'Lady Anfa (Casablanca)' };
      const sectorName = GYM_NAMES[sector] || sector || 'ALL EMPIRE';

      // ── KPI context ─────────────────────────────────────────────────────────
      const kpiContext = kpis ? [
        `GYM / SECTOR: ${sectorName}`,
        `Revenue  → Today: ${(kpis?.income?.day||0).toLocaleString()} DH | This week: ${(kpis?.income?.week||0).toLocaleString()} DH | This month: ${(kpis?.income?.month||0).toLocaleString()} DH | This year: ${(kpis?.income?.year||0).toLocaleString()} DH`,
        `New memberships → Today: ${kpis?.newMembers?.day||0} | This week: ${kpis?.newMembers?.week||0} | This month: ${kpis?.newMembers?.month||0}`,
        `Total active members: ${kpis?.totalActive || 'N/A'}`,
      ].join('\n') : `GYM / SECTOR: ${sectorName}\nNo KPI data available.`;

      // ── 30-day door traffic from SQLite ─────────────────────────────────────
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
      // ── Live door entries ────────────────────────────────────────────────────
      let liveContext = '';
      if (Array.isArray(liveEntries) && liveEntries.length > 0) {
        liveContext = `\n--- LIVE ENTRIES TODAY (${sectorName}) ---\n` +
          liveEntries.map(e => `  ${e.name||'?'} @ ${e.time ? new Date(e.time).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}) : '??:??'} (${e.source||'scan'})`).join('\n');
      }

      // ── Course & Reservation Context ─────────────────────────────────────────
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

      // ── Subscriptions Context ──────────────────────────────────────────────
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
      res.status(500).json({ error: 'Groq service unavailable', answer: '⚠️ Neural core offline.' });
    }
  });

  // \u2500\u2500 INCIDENTS (SQLite-backed, Firestore-write-through) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n  // Cache TTL: 10 minutes — avoids Firestore reads on every dashboard refresh\n  const INCIDENTS_TTL_MS = 10 * 60 * 1000;\n  let incidentsCachedAt = 0;\n\n  async function syncIncidentsFromFirestore() {\n    const now = Date.now();\n    if (now - incidentsCachedAt < INCIDENTS_TTL_MS) return; // still fresh\n    try {\n      const snap = await db.collection('incidents').orderBy('createdAt', 'desc').limit(200).get();\n      const rows = snap.docs.map(d => {\n        const data = d.data();\n        return {\n          id: d.id,\n          gymId: data.gymId || '',\n          gymName: data.gymName || '',\n          title: data.title || '',\n          cause: data.cause || '',\n          explanation: data.explanation || '',\n          emergency: data.emergency || 'Low',\n          status: data.status || 'Pending',\n          reporter: data.reporter || '',\n          date: data.date || '',\n          createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : new Date().toISOString(),\n        };\n      });\n      lc.upsertIncidents(rows);\n      incidentsCachedAt = now;\n      console.log(`\u26a1 [INCIDENTS] Synced ${rows.length} incidents to SQLite`);\n    } catch (err) {\n      console.error('[INCIDENTS] Firestore sync failed, serving stale cache:', err.message);\n    }\n  }\n\n  // GET /api/incidents — serve from SQLite, sync Firestore only when stale\n  router.get('/api/incidents', verifyAzureToken, async (req, res) => {\n    try {\n      await syncIncidentsFromFirestore();\n      const gymId = req.query.gymId || 'all';\n      const rows = lc.getIncidents(gymId);\n      // Normalize snake_case → camelCase for frontend\n      const out = rows.map(r => ({\n        id: r.id, gymId: r.gym_id, gymName: r.gym_name,\n        title: r.title, cause: r.cause, explanation: r.explanation,\n        emergency: r.emergency, status: r.status,\n        reporter: r.reporter, date: r.date, createdAt: r.created_at,\n      }));\n      res.json(out);\n    } catch (err) {\n      console.error('[INCIDENTS GET] error:', err);\n      res.status(500).json({ error: 'Failed to fetch incidents' });\n    }\n  });\n\n  // POST /api/incidents — write to Firestore + SQLite immediately\n  router.post('/api/incidents', verifyAzureToken, async (req, res) => {\n    try {\n      const { gymId, gymName, title, cause, explanation, emergency, reporter, date } = req.body;\n      const docRef = await db.collection('incidents').add({\n        gymId, gymName, title, cause, explanation, emergency,\n        reporter, date, status: 'Pending',\n        createdAt: admin.firestore.FieldValue.serverTimestamp(),\n        updatedAt: admin.firestore.FieldValue.serverTimestamp(),\n      });\n      const now = new Date().toISOString();\n      lc.upsertIncidents([{ id: docRef.id, gymId, gymName, title, cause, explanation, emergency, reporter, date, status: 'Pending', createdAt: now }]);\n      incidentsCachedAt = 0; // force refresh on next GET\n      res.json({ id: docRef.id, gymId, gymName, title, cause, explanation, emergency, reporter, date, status: 'Pending', createdAt: now });\n    } catch (err) {\n      console.error('[INCIDENTS POST] error:', err);\n      res.status(500).json({ error: 'Failed to create incident' });\n    }\n  });\n\n  // PATCH /api/incidents/:id/resolve — update SQLite instantly, Firestore in background\n  router.patch('/api/incidents/:id/resolve', verifyAzureToken, async (req, res) => {\n    try {\n      lc.resolveIncidentCache(req.params.id); // immediate SQLite update\n      // Fire-and-forget Firestore update (non-blocking)\n      db.collection('incidents').doc(req.params.id).update({\n        status: 'Resolved', updatedAt: admin.firestore.FieldValue.serverTimestamp()\n      }).catch(err => console.error('[INCIDENTS RESOLVE Firestore]', err.message));\n      res.json({ ok: true });\n    } catch (err) {\n      res.status(500).json({ error: 'Failed to resolve incident' });\n    }\n  });\n\n  return router;\n};\n
