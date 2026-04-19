'use strict';
// routes/register.js — Daily Register (Registre Journalier) + Calendar

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function registerRouter({ db, admin, lc, apiCache, isQuotaExceeded, getCachedOrFetch, invalidateCache }) {
  const router = Router();

  // ── GET /api/register ─────────────────────────────────────────────────────
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.query;
      if (!date) return res.status(400).json({ error: 'date required (YYYY-MM-DD)' });

      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : [gymId];
      let entries = [];

      // 1️⃣ Try SQLite cache first
      const cached = lc.getRegister(gymId, date);
      if (cached && cached.length > 0) {
        console.log(`⚡ [SQLITE HIT] ${cached.length} register entries for ${date}`);
        entries = cached.map(e => ({ ...e, createdAt: e.created_at }));
      } else {
        // 2️⃣ Firestore fallback
        if (isQuotaExceeded()) return res.status(429).json({ error: 'Quota exceeded. No local cache for this date.', quotaExceeded: true, entries: [] });
        console.log(`🌐 [SQLITE MISS] Fetching register from Firestore for ${date}...`);
        await Promise.all(gymIds.map(async (gid) => {
          const snap = await db.collection('megafit_daily_register').doc(`${gid}_${date}`).collection('entries').orderBy('createdAt', 'asc').get();
          const fetched = snap.docs.map(d => ({ id: d.id, gymId: gid, ...d.data() }));
          entries = entries.concat(fetched);
          if (fetched.length > 0) lc.upsertRegister(gid, date, fetched);
        }));
      }

      entries.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime() || 0);

      const totals = entries.reduce((acc, e) => ({
        tpe:      acc.tpe      + (Number(e.tpe)      || 0),
        espece:   acc.espece   + (Number(e.espece)   || 0),
        virement: acc.virement + (Number(e.virement) || 0),
        cheque:   acc.cheque   + (Number(e.cheque)   || 0),
      }), { tpe: 0, espece: 0, virement: 0, cheque: 0 });
      totals.ca = totals.tpe + totals.espece + totals.virement + totals.cheque;

      const byCommercial = {};
      entries.forEach(e => {
        const name = (e.commercial || '').trim().toUpperCase();
        if (!name) return;
        if (!byCommercial[name]) byCommercial[name] = { tpe: 0, espece: 0, virement: 0, cheque: 0, total: 0 };
        byCommercial[name].tpe      += Number(e.tpe)      || 0;
        byCommercial[name].espece   += Number(e.espece)   || 0;
        byCommercial[name].virement += Number(e.virement) || 0;
        byCommercial[name].cheque   += Number(e.cheque)   || 0;
        byCommercial[name].total    += (Number(e.tpe) || 0) + (Number(e.espece) || 0) + (Number(e.virement) || 0) + (Number(e.cheque) || 0);
      });

      res.json({ ok: true, date, gymId, entries, totals, byCommercial });
    } catch (err) {
      console.error('GET /api/register error:', err);
      res.status(500).json({ error: 'Failed to fetch register' });
    }
  });

  // ── POST /api/register/entry ──────────────────────────────────────────────
  router.post('/entry', async (req, res) => {
    try {
      const { date, gymId = 'dokarat', ...entry } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });
      const docId = `${gymId}_${date}`;
      const ref = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
        ...entry, location: gymId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: req.user?.preferred_username || 'system',
      });
      await db.collection('megafit_daily_register').doc(docId).set({ gymId, date, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      
      const newDoc = await ref.get();
      // ✅ Update the local SQLite cache directly so the new row appears immediately and survives refresh
      lc.upsertRegister(gymId, date, [{ id: ref.id, ...newDoc.data() }]);
      
      invalidateCache(apiCache.calendar, `${gymId}_${new Date(date).getFullYear()}`);
      res.json({ ok: true, id: ref.id });
    } catch (err) {
      console.error('POST /api/register/entry error:', err);
      res.status(500).json({ error: 'Failed to save entry' });
    }
  });

  // ── PUT /api/register/entry/:id ───────────────────────────────────────────
  // User requested bypassing Azure verification for now to allow editing quickly
  router.put('/entry/:id', async (req, res) => {
    try {
      const { date, gymId = 'dokarat', ...entry } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });
      
      const docRef = db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('entries').doc(req.params.id);
      await docRef.update({ ...entry, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      
      const updatedDoc = await docRef.get();
      // ✅ Update the local SQLite cache so the data doesn't revert to old values on page refresh
      lc.upsertRegister(gymId, date, [{ id: req.params.id, ...updatedDoc.data() }]);
      
      invalidateCache(apiCache.calendar, `${gymId}_${new Date(date).getFullYear()}`);
      res.json({ ok: true });
    } catch (err) {
      console.error('PUT /api/register/entry error:', err);
      res.status(500).json({ error: 'Failed to update entry' });
    }
  });

  // ── DELETE /api/register/entry/:id ───────────────────────────────────────
  router.delete('/entry/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.query;
      if (!date) return res.status(400).json({ error: 'date required' });
      await db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('entries').doc(req.params.id).delete();
      // ✅ Also remove from SQLite cache so it doesn't reappear on refresh
      lc.deleteRegisterEntry(gymId, date, req.params.id);
      invalidateCache(apiCache.calendar, `${gymId}_${new Date(date).getFullYear()}`);
      res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /api/register/entry error:', err);
      res.status(500).json({ error: 'Failed to delete entry' });
    }
  });

  // ── GET /api/register/calendar ────────────────────────────────────────────
  router.get('/calendar', verifyAzureToken, async (req, res) => {
    try {
      const { year = new Date().getFullYear(), gymId = 'dokarat' } = req.query;
      const cacheKey = `${gymId}_${year}`;

      const result = await getCachedOrFetch(apiCache.calendar, cacheKey, 10 * 60 * 1000, async () => {
        const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : [gymId];
        const calendarData = {}, resteData = {};

        await Promise.all(gymIds.map(async (gid) => {
          const prefix = `${gid}_${year}`;
          const snap = await db.collection('megafit_daily_register')
            .where(admin.firestore.FieldPath.documentId(), '>=', `${prefix}-01-01`)
            .where(admin.firestore.FieldPath.documentId(), '<=', `${prefix}-12-31`)
            .get();

          await Promise.all(snap.docs.map(async (parentDoc) => {
            const date = parentDoc.id.replace(`${gid}_`, '');
            const entriesSnap = await parentDoc.ref.collection('entries').get();
            let ca = 0, reste = 0;
            entriesSnap.docs.forEach(d => {
              const e = d.data();
              const paid = (Number(e.tpe) || 0) + (Number(e.espece) || 0) + (Number(e.virement) || 0) + (Number(e.cheque) || 0);
              ca += paid;
              const sr = Number(e.reste) || 0;
              if (sr > 0) reste += sr;
              else { const prix = Number(e.prix) || 0; if (prix > 0 && prix > paid) reste += prix - paid; }
            });
            calendarData[date] = (calendarData[date] || 0) + ca;
            if (reste > 0) resteData[date] = (resteData[date] || 0) + reste;
          }));
        }));

        return { calendarData, resteData };
      });

      res.json({ ok: true, gymId, year: Number(year), ...result });
    } catch (err) {
      console.error('GET /api/register/calendar error:', err);
      res.status(500).json({ error: 'Failed to fetch calendar' });
    }
  });

  return router;
};
