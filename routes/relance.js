'use strict';
// routes/relance.js — Relance (Follow-up) system: birthdays, expiring subs, inactive members
// All endpoints are under /api/relance/...
// Auth: Bearer token (verifyAzureToken) or fallback to x-inject-secret for service calls

const express = require('express');

// ── Commercial assignments per gym ────────────────────────────────────────────
const COMMERCIALS = {
  casa2:   ['Hiba Hidar', 'DALAL MOUSTAKIMI'],
  casa1:   ['BADR BOUMEDIANE', 'KHADIJA AZIZ', 'MOUSSA GHALLOU'],
  marjane: ['REDA', 'MARWA', 'SABER', 'AHLAM'],
  dokarat: ['OUISSALE', 'HAJAR'],
};

// Deterministic round-robin: assign commercial by hashing the member's primary key
function assignCommercial(gymId, primaryKey) {
  const commercials = COMMERCIALS[gymId] || [];
  if (!commercials.length) return 'Non assigné';
  // Simple hash: sum char codes of primaryKey, then mod
  let hash = 0;
  const key = String(primaryKey);
  for (let i = 0; i < key.length; i++) hash = (hash + key.charCodeAt(i)) & 0xffffffff;
  return commercials[Math.abs(hash) % commercials.length];
}

// ── Birthday helper messages per language ─────────────────────────────────────
const BIRTHDAY_SCRIPTS = [
  "🎂 Bonjour {nom} ! Toute l'équipe MegaFit vous souhaite un joyeux anniversaire ! C'est une journée spéciale pour vous, et nous voulions vous le dire. On vous offre une séance offerte ce mois-ci pour célébrer. Bonne fête !",
  "🥳 Allô {nom} ! Joyeux anniversaire de la part de MegaFit ! Nous sommes heureux de vous compter parmi nous. Profitez de votre journée spéciale !",
  "🎉 Bonjour {nom}, l'équipe MegaFit vous souhaite un très beau anniversaire ! N'hésitez pas à passer au club — on a une petite surprise pour vous. On vous attend !",
];

// ── UUID generator (crypto-less fallback) ─────────────────────────────────────
function uuid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

// ─────────────────────────────────────────────────────────────────────────────
module.exports = function createRelanceRouter(deps) {
  const { lc } = deps;
  const router = express.Router();

  // ── GET /api/relance/birthdays?gym=XXX&window=7 ──────────────────────────
  // Returns birthdays in the next N days (default 7) for the given gym.
  // Also returns the call log for each birthday entry.
  router.get('/birthdays', (req, res) => {
    try {
      const gymId  = req.query.gym;
      const window = parseInt(req.query.window, 10) || 7;

      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      // Build a set of (month, day) for today through today+window
      const dates = [];
      for (let i = 0; i < window; i++) {
        const d = new Date();
        d.setDate(d.getDate() + i);
        dates.push({ month: d.getMonth() + 1, day: d.getDate() });
      }

      // Fetch all matching birthdays
      const orClauses = dates.map(() => '(birth_month=? AND birth_day=?)').join(' OR ');
      const params    = [gymId, ...dates.flatMap(d => [d.month, d.day])];

      const birthdays = lc.db.prepare(
        `SELECT rb.*, rc.id as call_id, rc.called, rc.feedback, rc.comment, rc.call_date, rc.commercial as assigned_commercial
         FROM relance_birthdays rb
         LEFT JOIN relance_calls rc
           ON rc.birthday_id = rb.id AND rc.gym_id = rb.gym_id AND rc.list_type = 'birthday'
         WHERE rb.gym_id = ? AND (${orClauses})
         ORDER BY rb.birth_month, rb.birth_day, rb.full_name`
      ).all(...params);

      // Augment: add today flag, commercial assignment, birthday script
      const today = new Date();
      const result = birthdays.map((b, i) => {
        const isToday = b.birth_month === today.getMonth() + 1 && b.birth_day === today.getDate();
        const commercial = b.assigned_commercial || assignCommercial(gymId, b.phone || b.full_name);
        const script = BIRTHDAY_SCRIPTS[i % BIRTHDAY_SCRIPTS.length].replace('{nom}', b.full_name.split(' ')[0]);
        return { ...b, isToday, commercial, script };
      });

      res.json({ birthdays: result, total: result.length });
    } catch (err) {
      console.error('[relance/birthdays]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/relance/expiring?gym=XXX&window=30 ──────────────────────────
  // Members whose subscription expires within the next N days.
  router.get('/expiring', (req, res) => {
    try {
      const gymId  = req.query.gym;
      const window = parseInt(req.query.window, 10) || 30;

      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      const today     = new Date().toISOString().slice(0, 10);
      const future    = new Date(Date.now() + window * 86400000).toISOString().slice(0, 10);

      const members = lc.db.prepare(
        `SELECT mc.*, rc.id as call_id, rc.called, rc.feedback, rc.comment, rc.call_date, rc.commercial as assigned_commercial
         FROM members_cache mc
         LEFT JOIN relance_calls rc
           ON rc.member_id = mc.id AND rc.gym_id = mc.gym_id AND rc.list_type = 'expiring'
         WHERE mc.gym_id = ?
           AND mc.expires_on >= ? AND mc.expires_on <= ?
           AND (mc.status = 'Active' OR mc.status = 'active' OR mc.status = '')
           AND (mc.is_archive IS NULL OR mc.is_archive = 0)
         ORDER BY mc.expires_on ASC`
      ).all(gymId, today, future);

      const result = members.map(m => ({
        ...m,
        commercial: m.assigned_commercial || assignCommercial(gymId, m.id),
        daysLeft:   Math.ceil((new Date(m.expires_on) - new Date(today)) / 86400000),
      }));

      res.json({ members: result, total: result.length });
    } catch (err) {
      console.error('[relance/expiring]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/relance/inactive?gym=XXX&days=60 ────────────────────────────
  // Members who have had no door scan in the last N days (default 60).
  router.get('/inactive', (req, res) => {
    try {
      const gymId = req.query.gym;
      const days  = parseInt(req.query.days, 10) || 60;

      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      const cutoff = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

      // Members with no entry since cutoff and still active subscription
      const members = lc.db.prepare(
        `SELECT mc.*, rc.id as call_id, rc.called, rc.feedback, rc.comment, rc.call_date, rc.commercial as assigned_commercial,
                MAX(e.date) as last_visit
         FROM members_cache mc
         LEFT JOIN entries e ON (e.name LIKE '%' || mc.full_name || '%') AND e.gym_id = mc.gym_id
         LEFT JOIN relance_calls rc
           ON rc.member_id = mc.id AND rc.gym_id = mc.gym_id AND rc.list_type = 'inactive'
         WHERE mc.gym_id = ?
           AND (mc.status = 'Active' OR mc.status = 'active' OR mc.status = '')
           AND (mc.is_archive IS NULL OR mc.is_archive = 0)
           AND (mc.expires_on IS NULL OR mc.expires_on >= date('now'))
         GROUP BY mc.id
         HAVING (last_visit IS NULL OR last_visit < ?)
         ORDER BY last_visit ASC
         LIMIT 200`
      ).all(gymId, cutoff);

      const result = members.map(m => ({
        ...m,
        commercial: m.assigned_commercial || assignCommercial(gymId, m.id),
      }));

      res.json({ members: result, total: result.length });
    } catch (err) {
      console.error('[relance/inactive]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/relance/call ───────────────────────────────────────────────
  // Log or update a call record. Upsert by (gymId, listType, memberId/birthdayId).
  // Body: { gymId, listType, memberId?, birthdayId?, memberName, memberPhone?, commercial, called, feedback?, comment? }
  router.post('/call', (req, res) => {
    try {
      const {
        gymId, listType, memberId, birthdayId, memberName, memberPhone,
        commercial, called, feedback, comment,
      } = req.body;

      if (!gymId || !listType || !memberName || !commercial) {
        return res.status(400).json({ error: 'gymId, listType, memberName, commercial required' });
      }

      const now = new Date().toISOString();

      // Try to find existing record
      let existing = null;
      if (memberId) {
        existing = lc.db.prepare(
          `SELECT id FROM relance_calls WHERE gym_id=? AND list_type=? AND member_id=?`
        ).get(gymId, listType, memberId);
      } else if (birthdayId) {
        existing = lc.db.prepare(
          `SELECT id FROM relance_calls WHERE gym_id=? AND list_type=? AND birthday_id=?`
        ).get(gymId, listType, birthdayId);
      }

      if (existing) {
        lc.db.prepare(
          `UPDATE relance_calls
           SET called=?, feedback=?, comment=?, call_date=?, commercial=?, updated_at=?
           WHERE id=?`
        ).run(called ? 1 : 0, feedback || null, comment || null, called ? now.slice(0,10) : null, commercial, now, existing.id);
        return res.json({ ok: true, id: existing.id, action: 'updated' });
      }

      const id = uuid();
      lc.db.prepare(
        `INSERT INTO relance_calls
           (id, gym_id, list_type, member_id, birthday_id, member_name, member_phone, commercial, called, feedback, comment, call_date, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).run(
        id, gymId, listType,
        memberId || null, birthdayId || null,
        memberName, memberPhone || null, commercial,
        called ? 1 : 0,
        feedback || null, comment || null,
        called ? now.slice(0,10) : null,
        now, now,
      );

      res.json({ ok: true, id, action: 'created' });
    } catch (err) {
      console.error('[relance/call]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/relance/stats?gym=XXX ──────────────────────────────────────
  // Aggregated stats for the manager dashboard: calls made, feedback breakdown, per commercial.
  router.get('/stats', (req, res) => {
    try {
      const gymId = req.query.gym;
      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      const overall = lc.db.prepare(
        `SELECT
           list_type,
           COUNT(*) as total,
           SUM(called) as called,
           SUM(CASE WHEN feedback='positive' THEN 1 ELSE 0 END) as positive,
           SUM(CASE WHEN feedback='negative' THEN 1 ELSE 0 END) as negative,
           SUM(CASE WHEN feedback='no_answer' THEN 1 ELSE 0 END) as no_answer
         FROM relance_calls
         WHERE gym_id=?
         GROUP BY list_type`
      ).all(gymId);

      const perCommercial = lc.db.prepare(
        `SELECT
           commercial,
           list_type,
           COUNT(*) as total,
           SUM(called) as called,
           SUM(CASE WHEN feedback='positive' THEN 1 ELSE 0 END) as positive,
           SUM(CASE WHEN feedback='negative' THEN 1 ELSE 0 END) as negative,
           SUM(CASE WHEN feedback='no_answer' THEN 1 ELSE 0 END) as no_answer
         FROM relance_calls
         WHERE gym_id=?
         GROUP BY commercial, list_type
         ORDER BY commercial`
      ).all(gymId);

      // Birthday count for today
      const today = new Date();
      const todayBirthdays = lc.db.prepare(
        `SELECT COUNT(*) as n FROM relance_birthdays WHERE gym_id=? AND birth_month=? AND birth_day=?`
      ).get(gymId, today.getMonth() + 1, today.getDate());

      res.json({ overall, perCommercial, todayBirthdays: todayBirthdays?.n || 0 });
    } catch (err) {
      console.error('[relance/stats]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/relance/commercials?gym=XXX ────────────────────────────────
  // Returns the list of assigned commercials for a gym.
  router.get('/commercials', (req, res) => {
    const gymId = req.query.gym;
    if (!gymId) return res.status(400).json({ error: 'gym param required' });
    res.json({ commercials: COMMERCIALS[gymId] || [] });
  });

  // ── GET /api/relance/logs?gym=XXX&limit=200 ─────────────────────────────
  // Full call log for the dashboard history view (manager read-only).
  router.get('/logs', (req, res) => {
    try {
      const gymId = req.query.gym;
      const limit = parseInt(req.query.limit, 10) || 200;
      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      const logs = lc.db.prepare(
        `SELECT id, gym_id, list_type, member_id, member_name, member_phone,
                commercial, called, feedback, comment, call_date, created_at, updated_at
         FROM relance_calls
         WHERE gym_id = ?
         ORDER BY updated_at DESC
         LIMIT ?`
      ).all(gymId, limit);

      res.json({ logs, total: logs.length });
    } catch (err) {
      console.error('[relance/logs]', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
