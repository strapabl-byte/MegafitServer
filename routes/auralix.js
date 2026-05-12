'use strict';
// routes/auralix.js — Dedicated Auralix mini-app endpoints
// Uses Firebase ID token auth (not Azure) — for the PWA at /auralix/
// Reads revenue from SQLite register_cache (same source as Registre page)

const express = require('express');

module.exports = function(deps) {
  const { admin, lc } = deps;
  const router = express.Router();

  // ── Firebase token middleware ─────────────────────────────────
  async function firebaseAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    // Static readonly key — used in demo mode
    const AURALIX_KEY = process.env.AURALIX_API_KEY || 'auralix-readonly-2026';
    if (token === AURALIX_KEY) {
      req.auralixUser = { email: 'auralix-demo', role: 'admin' };
      return next();
    }

    if (!token) return res.status(401).json({ error: 'Missing token' });

    try {
      const decoded = await admin.auth().verifyIdToken(token);
      req.auralixUser = { email: decoded.email || decoded.uid, role: 'admin' };
      next();
    } catch(e) {
      return res.status(401).json({ error: 'Invalid Firebase token', detail: e.message });
    }
  }

  const GYMS = ['marjane', 'dokarat', 'casa1', 'casa2'];
  const GYM_NAMES = { marjane: 'Fès Saiss', dokarat: 'Dokarat', casa1: 'Casa Anfa', casa2: 'Lady Anfa' };

  // Build an array of date strings from today back N days: ['2026-05-12', '2026-05-11', ...]
  function dateRange(days) {
    const dates = [];
    const now = new Date();
    for (let i = 0; i < days; i++) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      dates.push(d.toISOString().slice(0, 10));
    }
    return dates;
  }

  // Query SQLite register_cache for a gym over a set of dates
  function getGymKpis(gymId, dates) {
    try {
      const placeholders = dates.map(() => '?').join(',');
      const rows = lc.db.prepare(
        `SELECT
           COALESCE(CAST(tpe AS REAL), 0) +
           COALESCE(CAST(espece AS REAL), 0) +
           COALESCE(CAST(virement AS REAL), 0) +
           COALESCE(CAST(cheque AS REAL), 0) AS row_total
         FROM register_cache
         WHERE gym_id = ? AND date IN (${placeholders})`
      ).all(gymId, ...dates);

      const revenue = rows.reduce((s, r) => s + (r.row_total || 0), 0);
      const members = rows.length;

      // Also count décaissements approved for these dates
      const decRows = lc.db.prepare(
        `SELECT COALESCE(CAST(montant AS REAL), 0) AS amt
         FROM decaissements_cache
         WHERE gym_id = ? AND date IN (${placeholders}) AND (status = 'approved' OR status IS NULL)`
      ).all(gymId, ...dates);
      const decaissement = decRows.reduce((s, r) => s + (r.amt || 0), 0);

      return { revenue: Math.round(revenue), members, decaissement: Math.round(decaissement) };
    } catch(e) {
      console.error(`[Auralix] SQLite error for ${gymId}:`, e.message);
      return { revenue: 0, members: 0, decaissement: 0 };
    }
  }

  // GET /api/auralix/summary?period=day|week|month
  router.get('/api/auralix/summary', firebaseAuth, (req, res) => {
    const period = req.query.period || 'day';
    const days = period === 'day' ? 1 : period === 'week' ? 7 : 30;
    const dates = dateRange(days);

    const gyms = GYMS.map(id => {
      const kpi = getGymKpis(id, dates);
      return { id, name: GYM_NAMES[id], ...kpi };
    });

    const total = gyms.reduce(
      (s, g) => ({ revenue: s.revenue + g.revenue, members: s.members + g.members, decaissement: s.decaissement + g.decaissement }),
      { revenue: 0, members: 0, decaissement: 0 }
    );

    console.log(`[Auralix] summary period=${period} dates=${dates[0]}..${dates[dates.length-1]} gyms=`, gyms.map(g => `${g.id}:${g.revenue}DH`).join(', '));

    res.json({ gyms, total, period, dates: { from: dates[dates.length - 1], to: dates[0] }, generatedAt: new Date().toISOString() });
  });

  // GET /api/auralix/ping — health check, no auth needed
  router.get('/api/auralix/ping', (req, res) => {
    // Also return SQLite row counts for debugging
    try {
      const regCount = lc.db.prepare('SELECT COUNT(*) as c FROM register_cache').get().c;
      const decCount = lc.db.prepare('SELECT COUNT(*) as c FROM decaissements_cache').get().c;
      res.json({ ok: true, ts: Date.now(), register_cache_rows: regCount, decaissements_cache_rows: decCount });
    } catch(e) {
      res.json({ ok: true, ts: Date.now(), sqlite_error: e.message });
    }
  });

  return router;
};
