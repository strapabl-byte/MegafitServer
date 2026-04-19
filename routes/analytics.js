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
      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : gymId.split(',');
      const dateStrs = Array.from({ length: 30 }, (_, i) => new Date(Date.now() + 3600000 - (29 - i) * 86400000).toISOString().slice(0, 10));
      const today = getMoroccanDateStr();
      const map = {};
      dateStrs.forEach(d => map[d] = { count: 0, rawCount: 0 });

      for (const gid of gymIds) {
        lc.getDailyStats(gid, 30).forEach(s => {
          if (map[s.date] && s.date !== today) { map[s.date].count += s.count || 0; map[s.date].rawCount += s.rawCount || 0; }
        });
        const cached = lc.getDailyStat(gid, today);
        const uniq   = lc.getUniqueEntryCount(gid, today);
        const raw    = lc.getEntryCount(gid, today);
        map[today].count    += cached ? Math.max(cached.count, uniq) : uniq;
        map[today].rawCount += cached ? Math.max(cached.raw_count, raw) : raw;
      }
      res.json(dateStrs.map(date => ({ gym_id: gymId, date, count: map[date].count, rawCount: map[date].rawCount })));
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
      if (cached && Date.now() - cached.ts < 2 * 60 * 1000) return res.json(cached.data);

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

      // ── Revenue from SQLite register cache (prix column, quota-free) ──
      const sumRegisterRevenue = (fromDate) => {
        let total = 0;
        const cursor = new Date(fromDate);
        while (cursor <= now) {
          const dateStr = toLocalDateStr(cursor);
          for (const gid of gymIds) {
            lc.getRegister(gid, dateStr).forEach(e => { total += (Number(e.prix) || 0); });
          }
          cursor.setDate(cursor.getDate() + 1);
        }
        return total;
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
        for (let i = 0; i < dayCount; i++) {
          const d = new Date(start); d.setDate(start.getDate() + i); if (d > now) break;
          const dateStr = toLocalDateStr(d);
          gymIds.forEach(gid => docRefs.push(db.collection('megafit_daily_register').doc(`${gid}_${dateStr}`).collection('entries')));
        }
        const snaps = await Promise.all(docRefs.map(r => r.get()));
        let total = 0;
        snaps.forEach(snap => snap.forEach(doc => {
          const e = doc.data();
          total += (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
        }));
        return total;
      };

      const monthCachedCount = countCachedEntries(monthStart);
      let incomeDay, incomeWeek, incomeMonth, incomeYear;

      if (monthCachedCount >= 3) {
        // SQLite has data — use it (fast, no quota cost)
        console.log(`✅ [KPI] SQLite: ${monthCachedCount} entries for ${gymId} — reading prix from local cache`);
        incomeDay   = sumRegisterRevenue(todayStart);
        incomeWeek  = sumRegisterRevenue(weekStart);
        incomeMonth = sumRegisterRevenue(monthStart);
        incomeYear  = sumRegisterRevenue(yearStart);
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
        income:     { day: incomeDay, week: incomeWeek, month: incomeMonth, year: incomeYear },
      };

      apiCache.kpis[gymId] = { data: kpis, ts: Date.now() };
      console.log(`📊 [KPI] ${gymId}: income day=${incomeDay} | week=${incomeWeek} | month=${incomeMonth} | year=${incomeYear} DH`);
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

  return router;
};
