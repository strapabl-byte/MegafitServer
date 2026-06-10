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

// ── Normalize name for fuzzy comparison ───────────────────────────────────────
function normName(s) {
  return (s || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

// ── Active subscriber detection ──────────────────────────────────────────────
// Cross-references a list of relance entries against members_cache to detect
// who has already renewed. Matches by BOTH full_name (fuzzy) AND phone.
// A family can share the same phone number, so phone-only is not enough.
function enrichWithActiveStatus(db, gymId, entries) {
  // Load all active members for this gym (non-archived, non-expired)
  const activeMembers = db.prepare(
    `SELECT full_name, phone, expires_on FROM members_cache
     WHERE gym_id = ?
       AND (is_archive IS NULL OR is_archive = 0)
       AND expires_on IS NOT NULL AND expires_on >= date('now')`
  ).all(gymId);

  // Pre-normalize for fast comparison
  const activeSet = activeMembers.map(m => ({
    name: normName(m.full_name),
    phone: (m.phone || '').replace(/\s+/g, '').replace(/^\+212/, '0'),
    expiresOn: m.expires_on,
  }));

  return entries.map(e => {
    const eName = normName(e.full_name || e.member_name || '');
    const ePhone = (e.phone || e.member_phone || '').replace(/\s+/g, '').replace(/^\+212/, '0');

    // Match: name must match (substring/startsWith) AND phone must match
    const match = activeSet.find(a => {
      const nameMatch = eName && a.name && (
        a.name === eName ||
        a.name.startsWith(eName) || eName.startsWith(a.name) ||
        a.name.includes(eName) || eName.includes(a.name)
      );
      const phoneMatch = ePhone && a.phone && (
        a.phone === ePhone ||
        a.phone.endsWith(ePhone.slice(-8)) && ePhone.length >= 8
      );
      // Require BOTH name AND phone to match (families share phone)
      return nameMatch && phoneMatch;
    });

    return {
      ...e,
      isActiveSubscriber: !!match,
      activeExpiresOn: match ? match.expiresOn : null,
    };
  });
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

      // Enrich with active subscriber detection
      const enriched = enrichWithActiveStatus(lc.db, gymId, result);
      res.json({ birthdays: enriched, total: enriched.length });
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

      // Enrich with active subscriber detection
      const enriched = enrichWithActiveStatus(lc.db, gymId, result);
      res.json({ members: enriched, total: enriched.length });
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

      // Enrich with active subscriber detection
      const enriched = enrichWithActiveStatus(lc.db, gymId, result);
      res.json({ members: enriched, total: enriched.length });
    } catch (err) {
      console.error('[relance/inactive]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/relance/expired?gym=XXX&days=90 ──────────────────────────────
  // Members whose subscription has expired within the last N days (default 90).
  // Pass days=0 for ALL expired members (no time limit).
  router.get('/expired', (req, res) => {
    try {
      const gymId = req.query.gym;
      const days  = parseInt(req.query.days, 10);
      const effectiveDays = isNaN(days) ? 90 : days;

      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      const today  = new Date().toISOString().slice(0, 10);

      // Build cutoff: if days=0, show ALL expired (no cutoff filter)
      const hasCutoff = effectiveDays > 0;
      const cutoff = hasCutoff ? new Date(Date.now() - effectiveDays * 86400000).toISOString().slice(0, 10) : null;

      const sql = `SELECT mc.*, rc.id as call_id, rc.called, rc.feedback, rc.comment, rc.call_date, rc.commercial as assigned_commercial
         FROM members_cache mc
         LEFT JOIN relance_calls rc
           ON rc.member_id = mc.id AND rc.gym_id = mc.gym_id AND rc.list_type = 'expired'
         WHERE mc.gym_id = ?
           AND mc.expires_on IS NOT NULL
           AND mc.expires_on < ?
           ${hasCutoff ? 'AND mc.expires_on >= ?' : ''}
           AND (mc.is_archive IS NULL OR mc.is_archive = 0)
         ORDER BY mc.expires_on DESC
         LIMIT 500`;

      const params = hasCutoff ? [gymId, today, cutoff] : [gymId, today];
      const members = lc.db.prepare(sql).all(...params);

      const result = members.map(m => {
        const daysSince = Math.ceil((new Date(today) - new Date(m.expires_on)) / 86400000);
        return {
          ...m,
          commercial: m.assigned_commercial || assignCommercial(gymId, m.id),
          daysSinceExpiry: daysSince,
        };
      });

      // Enrich with active subscriber detection (in case they re-subscribed)
      const enriched = enrichWithActiveStatus(lc.db, gymId, result);
      res.json({ members: enriched, total: enriched.length });
    } catch (err) {
      console.error('[relance/expired]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/relance/call ───────────────────────────────────────────────
  // Log or update a call record. Upsert by (gymId, listType, memberId/birthdayId).
  // Body: { gymId, listType, memberId?, birthdayId?, memberName, memberPhone?, commercial?, called, feedback?, comment? }
  router.post('/call', (req, res) => {
    try {
      const {
        gymId, listType, memberId, birthdayId, memberName, memberPhone,
        commercial, called, feedback, comment,
      } = req.body;

      // Only gymId and listType are strictly required — commercial & memberName have safe defaults
      if (!gymId || !listType) {
        return res.status(400).json({ error: 'gymId and listType required' });
      }

      const effectiveCommercial = commercial || 'Responsable';
      const effectiveName       = memberName  || 'Inconnu';
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
        ).run(called ? 1 : 0, feedback || null, comment || null, called ? now.slice(0,10) : null, effectiveCommercial, now, existing.id);
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
        effectiveName, memberPhone || null, effectiveCommercial,
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
    try {
      const gymId = req.query.gym;
      if (!gymId) return res.status(400).json({ error: 'gym param required' });
      
      const defaults = COMMERCIALS[gymId] || [];
      const loggedRows = lc.db.prepare(
        `SELECT DISTINCT commercial FROM relance_calls WHERE gym_id = ?`
      ).all(gymId);
      const loggedNames = loggedRows.map(r => r.commercial);
      
      const seen = new Set();
      const merged = [];
      
      // Keep order of defaults first
      for (const name of defaults) {
        const clean = (name || '').trim().toUpperCase();
        if (clean && !seen.has(clean)) {
          seen.add(clean);
          merged.push(name);
        }
      }
      
      // Append logged commercials
      for (const name of loggedNames) {
        const clean = (name || '').trim().toUpperCase();
        if (clean && !seen.has(clean)) {
          seen.add(clean);
          merged.push(name);
        }
      }
      
      res.json({ commercials: merged });
    } catch (err) {
      console.error('[relance/commercials]', err);
      res.status(500).json({ error: err.message });
    }
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

  // ── GET /api/relance/history?gym=XXX&limit=200&offset=0 ─────────────────
  // Completed calls with feedback/comment — for commercial history view.
  router.get('/history', (req, res) => {
    try {
      const gymId  = req.query.gym;
      const limit  = parseInt(req.query.limit,  10) || 200;
      const offset = parseInt(req.query.offset, 10) || 0;
      if (!gymId) return res.status(400).json({ error: 'gym param required' });

      const rows = lc.db.prepare(
        `SELECT id, gym_id, list_type, member_id, birthday_id, member_name, member_phone,
                commercial, called, feedback, comment, call_date, created_at, updated_at
         FROM relance_calls
         WHERE gym_id = ? AND called = 1
         ORDER BY updated_at DESC
         LIMIT ? OFFSET ?`
      ).all(gymId, limit, offset);

      const totalRow = lc.db.prepare(
        `SELECT COUNT(*) as n FROM relance_calls WHERE gym_id = ? AND called = 1`
      ).get(gymId);

      res.json({ history: rows, total: totalRow?.n || 0, limit, offset });
    } catch (err) {
      console.error('[relance/history]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/relance/import-birthdays ──────────────────────────────────
  // Bulk-import birthday rows from JSON. Protected by x-inject-secret header.
  // Body: { gymId, rows: [{ full_name, phone, birth_month, birth_day, birth_year }] }
  router.post('/import-birthdays', (req, res) => {
    const secret = process.env.INJECT_SECRET || 'megafit_inject_2024';
    if (req.headers['x-inject-secret'] !== secret) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    try {
      const { gymId, rows } = req.body;
      if (!gymId || !Array.isArray(rows)) {
        return res.status(400).json({ error: 'gymId and rows[] required' });
      }

      const insert = lc.db.prepare(
        `INSERT OR IGNORE INTO relance_birthdays
           (gym_id, full_name, phone, birth_month, birth_day, birth_year)
         VALUES (?, ?, ?, ?, ?, ?)`
      );

      const importMany = lc.db.transaction((items) => {
        let inserted = 0;
        for (const r of items) {
          const info = insert.run(
            gymId,
            (r.full_name || '').trim(),
            (r.phone   || '').trim() || null,
            parseInt(r.birth_month, 10) || null,
            parseInt(r.birth_day,   10) || null,
            parseInt(r.birth_year,  10) || null,
          );
          if (info.changes > 0) inserted++;
        }
        return inserted;
      });

      const inserted = importMany(rows);
      const total = lc.db.prepare('SELECT COUNT(*) as n FROM relance_birthdays WHERE gym_id=?').get(gymId);
      res.json({ ok: true, inserted, total: total?.n || 0 });
    } catch (err) {
      console.error('[relance/import-birthdays]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── PATCH /api/relance/call/:id ─────────────────────────────────────────
  // Reassign or update any field on an existing call log entry.
  // Body: { commercial?, called?, feedback?, comment? }
  router.patch('/call/:id', (req, res) => {
    try {
      const { id } = req.params;
      if (!id) return res.status(400).json({ error: 'id param required' });

      const row = lc.db.prepare(`SELECT id FROM relance_calls WHERE id=?`).get(id);
      if (!row) return res.status(404).json({ error: 'Call log not found' });

      const { commercial, called, feedback, comment } = req.body;
      const now = new Date().toISOString();

      const updates = [];
      const params  = [];

      if (commercial !== undefined) { updates.push('commercial=?');  params.push(commercial); }
      if (called     !== undefined) { updates.push('called=?');      params.push(called ? 1 : 0); }
      if (feedback   !== undefined) { updates.push('feedback=?');    params.push(feedback || null); }
      if (comment    !== undefined) { updates.push('comment=?');     params.push(comment  || null); }

      if (updates.length === 0) return res.status(400).json({ error: 'Nothing to update' });

      updates.push('updated_at=?');
      params.push(now);
      params.push(id);

      lc.db.prepare(`UPDATE relance_calls SET ${updates.join(', ')} WHERE id=?`).run(...params);

      res.json({ ok: true, id, updated: Object.fromEntries(
        updates.slice(0, -1).map((u, i) => [u.split('=')[0].trim(), params[i]])
      )});
    } catch (err) {
      console.error('[relance/call PATCH]', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
