'use strict';
// routes/auralix.js — Dedicated Auralix mini-app endpoints
// Uses Firebase ID token auth (not Azure) — for the PWA at /auralix/

const express = require('express');

module.exports = function(deps) {
  const { admin } = deps;
  const db = admin.firestore();
  const router = express.Router();

  // ── Firebase token middleware ─────────────────────────────────
  async function firebaseAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    // Allow a static Auralix API key as fallback
    const AURALIX_KEY = process.env.AURALIX_API_KEY || 'auralix-readonly-2026';
    if (token === AURALIX_KEY) {
      req.auralixUser = { email: 'auralix-app', role: 'admin' };
      return next();
    }

    if (!token) return res.status(401).json({ error: 'Missing token' });

    try {
      const decoded = await admin.auth().verifyIdToken(token);
      req.auralixUser = { email: decoded.email || decoded.uid, role: 'admin' };
      next();
    } catch(e) {
      return res.status(401).json({ error: 'Invalid Firebase token' });
    }
  }

  const GYMS = ['marjane', 'dokarat', 'casa1', 'casa2'];

  // Helper: sum register entries for a gym over N days
  async function getGymKpis(gymId, days) {
    const now = new Date();
    const cutoff = new Date(now);
    cutoff.setDate(cutoff.getDate() - days);

    // Build date strings for range
    const dateStrs = [];
    for (let i = 0; i <= days; i++) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      dateStrs.push(d.toISOString().slice(0, 10)); // YYYY-MM-DD
    }

    let revenue = 0, members = 0;

    try {
      const snap = await db.collection('daily_registers')
        .where('gymId', '==', gymId)
        .where('date', 'in', dateStrs.slice(0, 10)) // Firestore in[] limit 10
        .get();

      snap.forEach(doc => {
        const data = doc.data();
        const entries = data.entries || [];
        entries.forEach(e => {
          const tpe = Number(e.tpe) || 0;
          const esp = Number(e.espece) || 0;
          const vir = Number(e.virement) || 0;
          const chq = Number(e.cheque) || 0;
          revenue += tpe + esp + vir + chq;
          members += 1;
        });
      });
    } catch(e) {
      console.error(`Auralix KPI error for ${gymId}:`, e.message);
    }

    return { revenue, members };
  }

  // GET /api/auralix/summary?period=day|week|month
  router.get('/api/auralix/summary', firebaseAuth, async (req, res) => {
    const period = req.query.period || 'day';
    const days = period === 'day' ? 1 : period === 'week' ? 7 : 30;

    try {
      const results = await Promise.all(GYMS.map(id => getGymKpis(id, days)));

      const gyms = GYMS.map((id, i) => ({
        id,
        name: { marjane: 'Fès Saiss', dokarat: 'Dokarat', casa1: 'Casa Anfa', casa2: 'Lady Anfa' }[id],
        revenue: results[i].revenue,
        members: results[i].members,
      }));

      const total = gyms.reduce((s, g) => ({ revenue: s.revenue + g.revenue, members: s.members + g.members }), { revenue: 0, members: 0 });

      res.json({ gyms, total, period, generatedAt: new Date().toISOString() });
    } catch(e) {
      console.error('Auralix summary error:', e);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // GET /api/auralix/ping — health check (no auth)
  router.get('/api/auralix/ping', (req, res) => res.json({ ok: true, ts: Date.now() }));

  return router;
};
