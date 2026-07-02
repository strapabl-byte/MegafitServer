'use strict';
// routes/david.js — token-protected read bridge for the David WhatsApp agent.
// David authenticates with the shared secret (DAVID_NOTIFY_TOKEN) via x-notify-token.

const { Router } = require('express');

const GYM_LABELS = {
  dokarat: 'Fès Dukkarate',
  marjane: 'Fès Saïss',
  casa1: 'Casa Anfa',
  casa2: 'Casa Lady',
};

module.exports = function davidBridge({ lc }) {
  const router = Router();

  function auth(req, res, next) {
    const token = process.env.DAVID_NOTIFY_TOKEN;
    if (!token) return res.status(503).json({ ok: false, error: 'bridge disabled (no token)' });
    if (String(req.headers['x-notify-token'] || '') !== token) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    next();
  }

  // GET /api/david/incidents?scope=today|open|all&gymId=casa1
  router.get('/api/david/incidents', auth, (req, res) => {
    try {
      const scope = String(req.query.scope || 'today').toLowerCase();
      const gymId = String(req.query.gymId || '').toLowerCase().trim();
      const today = new Date().toISOString().slice(0, 10);

      let sql =
        'SELECT id, gym_id, title, cause, explanation, emergency, status, reporter, date, created_at FROM incidents_cache';
      const where = [];
      const params = [];
      if (scope === 'today') {
        where.push('date = ?');
        params.push(today);
      } else if (scope === 'open') {
        where.push("status != 'Resolved'");
      }
      if (gymId && GYM_LABELS[gymId]) {
        where.push('gym_id = ?');
        params.push(gymId);
      }
      if (where.length) sql += ' WHERE ' + where.join(' AND ');
      sql += ' ORDER BY created_at DESC LIMIT 50';

      const rows = lc && lc.db ? lc.db.prepare(sql).all(...params) : [];
      const incidents = rows.map((r) => ({
        gym: GYM_LABELS[r.gym_id] || r.gym_id,
        title: r.title,
        cause: r.cause,
        explanation: r.explanation,
        emergency: r.emergency,
        status: r.status,
        reporter: r.reporter,
        date: r.date,
      }));

      res.json({ ok: true, scope, count: incidents.length, incidents });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  return router;
};
