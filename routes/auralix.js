'use strict';
// routes/auralix.js — Auralix PWA API (Firebase token auth)
const express = require('express');

module.exports = function(deps) {
  const { admin, lc } = deps;
  const fsDb = admin.firestore();
  const router = express.Router();

  // ── Auth middleware ───────────────────────────────────────────
  async function auth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const KEY = process.env.AURALIX_API_KEY || 'auralix-readonly-2026';
    if (token === KEY) { req.au = { email: 'demo' }; return next(); }
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const d = await admin.auth().verifyIdToken(token);
      req.au = { email: d.email || d.uid };
      next();
    } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
  }

  const GYMS = ['marjane', 'dokarat', 'casa1', 'casa2'];
  const NAMES = { marjane: 'Fès Saiss', dokarat: 'Dokarat', casa1: 'Casa Anfa', casa2: 'Lady Anfa' };

  function dateRange(days) {
    const dates = [];
    for (let i = 0; i < days; i++) {
      const d = new Date(); d.setDate(d.getDate() - i);
      dates.push(d.toISOString().slice(0, 10));
    }
    return dates;
  }

  function gymRevenue(gymId, dates) {
    try {
      const ph = dates.map(() => '?').join(',');
      const rows = lc.db.prepare(
        `SELECT COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0) AS t
         FROM register_cache WHERE gym_id=? AND date IN (${ph})`
      ).all(gymId, ...dates);
      const revenue = Math.round(rows.reduce((s, r) => s + (r.t || 0), 0));
      const dec = lc.db.prepare(
        `SELECT COALESCE(CAST(montant AS REAL),0) AS m FROM decaissements_cache
         WHERE gym_id=? AND date IN (${ph}) AND (status='approved' OR status IS NULL)`
      ).all(gymId, ...dates);
      const decaissement = Math.round(dec.reduce((s, r) => s + (r.m || 0), 0));
      return { revenue, members: rows.length, decaissement, net: revenue - decaissement };
    } catch(e) { return { revenue: 0, members: 0, decaissement: 0, net: 0 }; }
  }

  // GET /api/auralix/summary?period=24h|week|month
  router.get('/api/auralix/summary', auth, (req, res) => {
    const p = req.query.period || '24h';
    const days = p === '24h' ? 2 : p === 'week' ? 7 : 30; // 2 days covers last 24h
    const dates = dateRange(days);
    const gyms = GYMS.map(id => ({ id, name: NAMES[id], ...gymRevenue(id, dates) }));
    const total = gyms.reduce((s, g) => ({
      revenue: s.revenue + g.revenue,
      members: s.members + g.members,
      decaissement: s.decaissement + g.decaissement,
      net: s.net + g.net,
    }), { revenue: 0, members: 0, decaissement: 0, net: 0 });
    res.json({ gyms, total, period: p });
  });

  // GET /api/auralix/transactions?hours=24
  router.get('/api/auralix/transactions', auth, (req, res) => {
    const hours = Math.min(parseInt(req.query.hours) || 24, 168);
    try {
      // Try created_at first, fall back to last 2 dates
      let rows = lc.db.prepare(
        `SELECT id, gym_id, date, nom, abonnement, commercial,
                ROUND(COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0)) AS montant,
                COALESCE(CAST(tpe AS REAL),0) AS tpe, COALESCE(CAST(espece AS REAL),0) AS espece,
                COALESCE(CAST(virement AS REAL),0) AS virement, COALESCE(CAST(cheque AS REAL),0) AS cheque,
                created_at
         FROM register_cache
         WHERE created_at >= datetime('now', ?)
         ORDER BY created_at DESC LIMIT 80`
      ).all(`-${hours} hours`);

      // If created_at is empty/missing, fall back to date-based
      if (rows.length === 0) {
        const dates = dateRange(Math.ceil(hours / 24) + 1);
        const ph = dates.map(() => '?').join(',');
        rows = lc.db.prepare(
          `SELECT id, gym_id, date, nom, abonnement, commercial,
                  ROUND(COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0)) AS montant,
                  COALESCE(CAST(tpe AS REAL),0) AS tpe, COALESCE(CAST(espece AS REAL),0) AS espece,
                  COALESCE(CAST(virement AS REAL),0) AS virement, COALESCE(CAST(cheque AS REAL),0) AS cheque,
                  created_at
           FROM register_cache WHERE date IN (${ph}) ORDER BY created_at DESC, rowid DESC LIMIT 80`
        ).all(...dates);
      }

      // Add payment method label
      const txns = rows.filter(r => r.montant > 0).map(r => ({
        ...r,
        gymName: NAMES[r.gym_id] || r.gym_id,
        method: r.tpe > 0 ? 'TPE' : r.espece > 0 ? 'ESPÈCE' : r.virement > 0 ? 'VIREMENT' : r.cheque > 0 ? 'CHÈQUE' : '?',
      }));
      res.json({ transactions: txns, count: txns.length });
    } catch(e) {
      console.error('[Auralix] transactions error:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/auralix/decaissements?status=pending|all
  router.get('/api/auralix/decaissements', auth, (req, res) => {
    const status = req.query.status || 'pending';
    try {
      const where = status === 'all' ? '' : `WHERE status = 'pending' OR status IS NULL`;
      const rows = lc.db.prepare(
        `SELECT id, gym_id, date, montant, raison, signature, requestedBy, status
         FROM decaissements_cache ${where} ORDER BY date DESC LIMIT 50`
      ).all();
      res.json({ decaissements: rows.map(r => ({ ...r, gymName: NAMES[r.gym_id] || r.gym_id })) });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/auralix/decaissements/:id/approve  body: { gymId, date }
  router.post('/api/auralix/decaissements/:id/approve', auth, async (req, res) => {
    const { id } = req.params;
    const { gymId, date } = req.body;
    if (!gymId || !date) return res.status(400).json({ error: 'gymId and date required' });
    try {
      // 1. Update SQLite
      lc.db.prepare(`UPDATE decaissements_cache SET status='approved' WHERE id=?`).run(id);
      // 2. Update Firestore
      const docRef = fsDb.collection('megafit_daily_register').doc(`${gymId}_${date}`)
                         .collection('decaissements').doc(id);
      await docRef.update({ status: 'approved', approvedAt: admin.firestore.FieldValue.serverTimestamp(), approvedBy: req.au?.email || 'auralix' });
      console.log(`[Auralix] Approved décaissement ${id} for ${gymId} on ${date}`);
      res.json({ ok: true, id, status: 'approved' });
    } catch(e) {
      console.error('[Auralix] approve error:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/auralix/decaissements/:id/reject  body: { gymId, date }
  router.post('/api/auralix/decaissements/:id/reject', auth, async (req, res) => {
    const { id } = req.params;
    const { gymId, date } = req.body;
    try {
      lc.db.prepare(`UPDATE decaissements_cache SET status='rejected' WHERE id=?`).run(id);
      const docRef = fsDb.collection('megafit_daily_register').doc(`${gymId}_${date}`)
                         .collection('decaissements').doc(id);
      await docRef.update({ status: 'rejected', rejectedAt: admin.firestore.FieldValue.serverTimestamp(), rejectedBy: req.au?.email || 'auralix' });
      res.json({ ok: true, id, status: 'rejected' });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Ping
  router.get('/api/auralix/ping', (req, res) => {
    try {
      const rc = lc.db.prepare('SELECT COUNT(*) as c FROM register_cache').get().c;
      res.json({ ok: true, register_cache_rows: rc, ts: Date.now() });
    } catch(e) { res.json({ ok: true, ts: Date.now() }); }
  });

  return router;
};
