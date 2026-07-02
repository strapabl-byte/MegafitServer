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

module.exports = function davidBridge({ db, lc }) {
  const router = Router();

  // Live progress for a challenge/goal, computed from the register (same logic as /api/commercials/goals).
  function challengeProgress(g) {
    const hasRange = g.startDate && g.endDate;
    if ((!hasRange && !g.period) || !lc || !lc.db) return { currentRevenue: 0, currentInscriptions: 0 };
    const targetGyms = g.gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : [g.gymId];
    const ph = targetGyms.map(() => '?').join(',');
    const dateWhere = hasRange ? 'date >= ? AND date <= ?' : 'date LIKE ?';
    const dateArgs = hasRange ? [g.startDate, g.endDate] : [`${g.period}%`];
    const row = lc.db
      .prepare(
        `SELECT SUM(CASE WHEN COALESCE(source,'') != 'reste_settlement' THEN 1 ELSE 0 END) as inscriptions,
                SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as revenue
         FROM register_cache WHERE gym_id IN (${ph}) AND ${dateWhere}`,
      )
      .get(...targetGyms, ...dateArgs);
    return { currentRevenue: Math.round(row?.revenue || 0), currentInscriptions: row?.inscriptions || 0 };
  }

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

  // GET /api/david/challenges?scope=ongoing|all&gymId=casa1
  // Sales challenges (Défi hebdo/libre + objectif mensuel) with live progress per club.
  router.get('/api/david/challenges', auth, async (req, res) => {
    try {
      if (!db) return res.json({ ok: true, count: 0, challenges: [] });
      const scope = String(req.query.scope || 'ongoing').toLowerCase();
      const gymId = String(req.query.gymId || '').toLowerCase().trim();
      const today = new Date().toISOString().slice(0, 10);
      const month = today.slice(0, 7);

      const snap = await db.collection('commercial_goals').get();
      const challenges = [];
      snap.forEach((doc) => {
        const g = { id: doc.id, ...doc.data() };
        if (g.active === false) return;
        if (gymId && GYM_LABELS[gymId] && g.gymId !== gymId && g.gymId !== 'all') return;

        const hasRange = Boolean(g.startDate && g.endDate);
        const ongoing = hasRange ? g.startDate <= today && today <= g.endDate : g.period === month;
        if (scope === 'ongoing' && !ongoing) return;

        const prog = challengeProgress(g);
        const targetRev = Number(g.targetRevenue) || 0;
        const targetIns = Number(g.targetInscriptions) || 0;
        challenges.push({
          gym: g.gymId === 'all' ? 'Tous les clubs' : GYM_LABELS[g.gymId] || g.gymId,
          type: hasRange ? 'défi hebdo/libre' : 'objectif mensuel',
          label: g.label || g.period || '',
          period: hasRange ? `${g.startDate} → ${g.endDate}` : g.period,
          ongoing,
          targetRevenue: targetRev,
          currentRevenue: prog.currentRevenue,
          pctRevenue: targetRev > 0 ? Math.round((prog.currentRevenue / targetRev) * 100) : null,
          targetInscriptions: targetIns,
          currentInscriptions: prog.currentInscriptions,
          reward: g.reward || '',
        });
      });

      challenges.sort((a, b) => Number(b.ongoing) - Number(a.ongoing) || (b.pctRevenue || 0) - (a.pctRevenue || 0));
      res.json({ ok: true, scope, count: challenges.length, challenges });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  return router;
};
