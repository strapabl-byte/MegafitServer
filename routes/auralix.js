'use strict';
// routes/auralix.js — Auralix PWA API (Firebase token auth)
const express = require('express');

module.exports = function(deps) {
  const { admin, lc } = deps;
  const fsDb = admin.firestore();
  const router = express.Router();
  const { verifyAzureToken } = require('../middleware/auth');
  const { notifyDavidDecaissement } = require('../services/david-notify');

  // Unified Auth Wrapper for Auralix
  function auth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const KEY = process.env.AURALIX_API_KEY;
    if (!KEY) console.error('[Auralix] WARNING: AURALIX_API_KEY env var not set! API key auth is disabled.');
    if (token === KEY) { req.au = { email: 'demo' }; return next(); }
    
    // Use the dashboard's enterprise auth
    verifyAzureToken(req, res, () => {
      req.au = { email: req.user?.preferred_username || req.user?.email || 'authenticated' };
      next();
    });
  }

  const GYMS = ['marjane', 'dokarat', 'casa1', 'casa2'];
  const NAMES = { marjane: 'Fès Saiss', dokarat: 'Dokarat', casa1: 'Casa Anfa', casa2: 'Casa Lady' };

  function dateRange(days) {
    const dates = [];
    const moroccoNow = new Date(Date.now() + 3600000); // UTC+1
    const moroccoHour = moroccoNow.getUTCHours();
    // Before 6AM: start from yesterday (business day not started)
    const start = new Date(moroccoNow);
    if (moroccoHour < 6) start.setUTCDate(start.getUTCDate() - 1);
    for (let i = 0; i < days; i++) {
      const d = new Date(start);
      d.setUTCDate(d.getUTCDate() - i);
      dates.push(d.toISOString().slice(0, 10));
    }
    return dates;
  }

  // Returns today's date string (Morocco UTC+1), but before 6AM treat as yesterday
  // so the business day resets at 6:00 AM, not midnight
  function todayDate() {
    const moroccoHour = (new Date().getUTCHours() + 1) % 24;
    const d = new Date(Date.now() + 3600000); // shift to Morocco time
    if (moroccoHour < 6) d.setUTCDate(d.getUTCDate() - 1); // before 6AM → yesterday
    return d.toISOString().slice(0, 10);
  }

  // Returns all dates from 1st of current month to today
  function thisMonthDates() {
    const now = new Date(Date.now() + 3600000);
    const today = now.toISOString().slice(0, 10);
    const year = now.getUTCFullYear();
    const month = now.getUTCMonth();
    const daysInMonth = now.getUTCDate(); // days elapsed this month
    const dates = [];
    for (let d = 1; d <= daysInMonth; d++) {
      const dd = new Date(Date.UTC(year, month, d));
      dates.push(dd.toISOString().slice(0, 10));
    }
    return dates;
  }

  function gymRevenue(gymId, dates) {
    try {
      const ph = dates.map(() => '?').join(',');
      const rows = lc.db.prepare(
        `SELECT COALESCE(CAST(tpe AS REAL),0) AS tpe,
                COALESCE(CAST(espece AS REAL),0) AS espece,
                COALESCE(CAST(virement AS REAL),0) AS virement,
                COALESCE(CAST(cheque AS REAL),0) AS cheque,
                COALESCE(CAST(prix AS REAL),0) AS prix,
                COALESCE(CAST(reste AS REAL),0) AS stored_reste,
                COALESCE(source, '') AS source,
                COALESCE(nom, '') AS nom,
                COALESCE(contrat, '') AS contrat
         FROM register_cache WHERE gym_id=? AND date IN (${ph})`
      ).all(gymId, ...dates);
      const espece   = Math.round(rows.reduce((s, r) => s + (r.espece || 0), 0));
      const tpe      = Math.round(rows.reduce((s, r) => s + (r.tpe || 0), 0));
      const virement = Math.round(rows.reduce((s, r) => s + (r.virement || 0), 0));
      const cheque   = Math.round(rows.reduce((s, r) => s + (r.cheque || 0), 0));

      // 🔧 FIX: Build settled member map to exclude already-paid debts
      const settledRows = lc.db.prepare(
        `SELECT nom, contrat, CAST(reste AS REAL) AS reste
         FROM register_cache
         WHERE gym_id = ? AND COALESCE(source, '') = 'reste_settlement'`
      ).all(gymId);
      const settledMap = new Map();
      for (const s of settledRows) {
        const key = (s.contrat && s.contrat.trim() && s.contrat.trim() !== '-')
          ? `contrat:${s.contrat.trim()}`
          : `nom:${(s.nom || '').trim().toUpperCase()}`;
        const existing = settledMap.get(key);
        if (!existing || (s.reste || 0) < existing) {
          settledMap.set(key, s.reste || 0);
        }
      }

      // Smart reste calculation: recalculate from prix - paid (like frontend)
      // Exclude reste_settlement entries (they are payments, not debts)
      let reste = 0, resteCount = 0;
      for (const r of rows) {
        if (r.source === 'reste_settlement') continue; // skip payment entries
        const paid = (r.tpe || 0) + (r.espece || 0) + (r.virement || 0) + (r.cheque || 0);
        const prix = r.prix || 0;
        let computedReste = 0;
        if (prix > 0) {
          computedReste = prix - paid;
        } else if ((r.stored_reste || 0) > 0) {
          computedReste = r.stored_reste;
        }
        if (computedReste > 0) {
          // Check if this member's debt has been settled
          const contratKey = (r.contrat && r.contrat.trim() && r.contrat.trim() !== '-')
            ? `contrat:${r.contrat.trim()}`
            : null;
          const nomKey = `nom:${(r.nom || '').trim().toUpperCase()}`;
          const settledReste = settledMap.get(contratKey) ?? settledMap.get(nomKey) ?? null;
          if (settledReste !== null) {
            if (settledReste > 0) { reste += settledReste; resteCount++; }
            // settledReste === 0 → fully paid, skip
          } else {
            reste += computedReste; resteCount++;
          }
        }
      }
      reste = Math.round(reste);

      const revenue  = espece + tpe + virement + cheque;
      const dec = lc.db.prepare(
        `SELECT COALESCE(CAST(montant AS REAL),0) AS m FROM decaissements_cache
         WHERE gym_id=? AND date IN (${ph}) AND (status IS NULL OR status != 'rejected')`
      ).all(gymId, ...dates);
      const decaissement = Math.round(dec.reduce((s, r) => s + (r.m || 0), 0));
      return { revenue, members: rows.length, entries: rows.length, decaissement, net: revenue - decaissement,
               espece, tpe, virement, cheque, reste, resteCount };
    } catch(e) { return { revenue: 0, members: 0, entries: 0, decaissement: 0, net: 0, espece: 0, tpe: 0, virement: 0, cheque: 0, reste: 0, resteCount: 0 }; }
  }

  // Real DOOR entries (physical turnstile scans) for a gym over a date range —
  // the same live door feed the main dashboard shows, from daily_stats.count.
  function doorEntries(gymId, dates) {
    try {
      if (!dates.length) return 0;
      const ph = dates.map(() => '?').join(',');
      const r = lc.db.prepare(
        `SELECT COALESCE(SUM(CAST(count AS INTEGER)),0) AS c FROM daily_stats WHERE gym_id=? AND date IN (${ph})`
      ).get(gymId, ...dates);
      return r?.c || 0;
    } catch { return 0; }
  }

  // The equal-length window immediately BEFORE the given dates (for trend arrows).
  function previousWindow(dates) {
    if (!dates.length) return [];
    const earliest = new Date([...dates].sort()[0] + 'T00:00:00Z');
    const prev = [];
    for (let i = 1; i <= dates.length; i++) {
      const d = new Date(earliest); d.setUTCDate(d.getUTCDate() - i);
      prev.push(d.toISOString().slice(0, 10));
    }
    return prev;
  }

  // GET /api/auralix/summary?period=today|week|month
  router.get('/api/auralix/summary', auth, (req, res) => {
    const p = req.query.period || 'today';
    let dates;
    if (p === 'today' || p === '24h') {
      dates = [todayDate()];
    } else if (p === 'month') {
      dates = thisMonthDates();
    } else if (p === 'week') {
      dates = dateRange(7);
    } else if (p === 'range' && req.query.days) {
      dates = dateRange(Math.min(parseInt(req.query.days), 365));
    } else if (p === 'date' && req.query.date) {
      dates = [req.query.date];
    } else {
      dates = [todayDate()];
    }
    const gyms = GYMS.map(id => ({ id, name: NAMES[id], ...gymRevenue(id, dates), doorEntries: doorEntries(id, dates) }));
    const total = gyms.reduce((s, g) => ({
      revenue: s.revenue + g.revenue,
      members: s.members + g.members,
      entries: s.entries + g.entries,
      doorEntries: s.doorEntries + (g.doorEntries || 0),
      decaissement: s.decaissement + g.decaissement,
      net: s.net + g.net,
      espece: s.espece + (g.espece || 0),
      tpe: s.tpe + (g.tpe || 0),
      virement: s.virement + (g.virement || 0),
      cheque: s.cheque + (g.cheque || 0),
      reste: s.reste + (g.reste || 0),
      resteCount: s.resteCount + (g.resteCount || 0),
    }), { revenue: 0, members: 0, entries: 0, doorEntries: 0, decaissement: 0, net: 0, espece: 0, tpe: 0, virement: 0, cheque: 0, reste: 0, resteCount: 0 });

    // Previous equal-length period (per gym) so the PWA can draw trend arrows,
    // correctly even when a single gym is selected.
    const prevDates = previousWindow(dates);
    const prevGyms = GYMS.map(id => {
      const r = gymRevenue(id, prevDates);
      return { id, revenue: r.revenue, net: r.net, members: r.members, doorEntries: doorEntries(id, prevDates) };
    });

    res.json({ gyms, total, prevGyms, period: p });
  });

  // GET /api/auralix/transactions?period=today|week|month
  router.get('/api/auralix/transactions', auth, (req, res) => {
    const period = req.query.period || req.query.hours ? null : 'today';
    const hours = Math.min(parseInt(req.query.hours) || 24, 168);
    try {
      // Build date list based on period
      let filterDates;
      if (req.query.period === 'today' || (!req.query.period && !req.query.hours)) {
        filterDates = [todayDate()];
      } else if (req.query.period === 'month') {
        filterDates = thisMonthDates();
      } else if (req.query.period === 'week') {
        filterDates = dateRange(7);
      } else if (req.query.period === 'range' && req.query.days) {
        filterDates = dateRange(Math.min(parseInt(req.query.days), 365));
      } else if (req.query.period === 'date' && req.query.date) {
        filterDates = [req.query.date];
      } else {
        filterDates = null;
      }

      let rows;
      if (filterDates) {
        // Date-based filter (exact calendar days)
        const ph = filterDates.map(() => '?').join(',');
        rows = lc.db.prepare(
          `SELECT id, gym_id, date, nom, abonnement, commercial,
                  ROUND(COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0)) AS montant,
                  COALESCE(CAST(tpe AS REAL),0) AS tpe, COALESCE(CAST(espece AS REAL),0) AS espece,
                  COALESCE(CAST(virement AS REAL),0) AS virement, COALESCE(CAST(cheque AS REAL),0) AS cheque,
                  COALESCE(CAST(reste AS REAL),0) AS reste, created_at
           FROM register_cache WHERE date IN (${ph}) ORDER BY created_at DESC, rowid DESC LIMIT 200`
        ).all(...filterDates);
      } else {
        // Legacy hours-based filter
        rows = lc.db.prepare(
          `SELECT id, gym_id, date, nom, abonnement, commercial,
                  ROUND(COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0)) AS montant,
                  COALESCE(CAST(tpe AS REAL),0) AS tpe, COALESCE(CAST(espece AS REAL),0) AS espece,
                  COALESCE(CAST(virement AS REAL),0) AS virement, COALESCE(CAST(cheque AS REAL),0) AS cheque,
                  COALESCE(CAST(reste AS REAL),0) AS reste,
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
                    COALESCE(CAST(reste AS REAL),0) AS reste,
                    created_at
             FROM register_cache WHERE date IN (${ph}) ORDER BY created_at DESC, rowid DESC LIMIT 80`
          ).all(...dates);
        }
      }

      // Add payment method label
      const txns = rows.filter(r => r.montant > 0).map(r => {
        const methods = [];
        if (r.tpe > 0) methods.push('TPE');
        if (r.espece > 0) methods.push('ESPÈCE');
        if (r.virement > 0) methods.push('VIREMENT');
        if (r.cheque > 0) methods.push('CHÈQUE');
        const methodLabel = methods.length > 0 ? methods.join(' + ') : '?';
        return {
          ...r,
          gymName: NAMES[r.gym_id] || r.gym_id,
          method: methodLabel,
        };
      });
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
        `SELECT id, gym_id, date, montant, raison, commercial, signature, requested_by, status, created_at
         FROM decaissements_cache ${where} ORDER BY date DESC LIMIT 50`
      ).all();
      res.json({
        decaissements: rows.map(r => ({
          ...r,
          requestedBy: r.requested_by,
          gymName: NAMES[r.gym_id] || r.gym_id
        }))
      });
    } catch(e) {
      console.error('[Auralix] decaissements error:', e.message);
      res.status(500).json({ error: e.message });
    }
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
      const row = lc.db.prepare('SELECT * FROM decaissements_cache WHERE id=?').get(id) || {};
      notifyDavidDecaissement({
        event: 'approved',
        montant: row.montant,
        raison: row.raison,
        requestedBy: row.requested_by,
        gymId,
        status: 'approved',
      });
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
      const row = lc.db.prepare('SELECT * FROM decaissements_cache WHERE id=?').get(id) || {};
      notifyDavidDecaissement({
        event: 'rejected',
        montant: row.montant,
        raison: row.raison,
        requestedBy: row.requested_by,
        gymId,
        status: 'rejected',
      });
      res.json({ ok: true, id, status: 'rejected' });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });
  // ── GET /api/auralix/locked-inscriptions ──────────────────────────────────
  router.get('/api/auralix/locked-inscriptions', auth, async (req, res) => {
    try {
      const snap = await fsDb.collection('pending_members')
        .where('source', '==', 'web')
        .where('status', '==', 'locked')
        .get();

      const GYM_NAMES = { dokarat: 'Fès Doukkarate', marjane: 'Fès Saïss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };

      const items = snap.docs.map(d => {
        const data = d.data();
        return {
          id: d.id,
          prenom: data.prenom || '',
          nom: data.nom || '',
          telephone: data.telephone || '',
          gymId: data.gymId || '',
          gymName: GYM_NAMES[data.gymId] || data.gymId || '',
          subscriptionName: data.subscriptionName || '',
          totalDue: data.totals?.total || 0,
          totalPaid: data.totals?.paid || 0,
          lockedBy: data.lockedBy || '',
          contractNumber: data.contractNumber || '',
          createdAt: data.createdAt?._seconds || 0,
          pdfUrl: data.pdfUrl || null,
        };
      }).sort((a, b) => b.createdAt - a.createdAt);

      res.json(items);
    } catch (e) {
      console.error('[Auralix] Locked inscriptions error:', e);
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /api/auralix/inscriptions/:id/approve ──────────────────────────
  // 🔒 SECURED: Azure AD + Admin only — API key is NOT sufficient for write operations
  const { requireAdmin } = require('../middleware/auth');
  router.post('/api/auralix/inscriptions/:id/approve', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { action } = req.body; // 'approve' or 'reject'
      const insRef = fsDb.collection('pending_members').doc(req.params.id);
      const insDoc = await insRef.get();
      if (!insDoc.exists) return res.status(404).json({ error: 'Inscription introuvable' });

      if (action === 'reject') {
        await insRef.delete();
        console.log(`[Auralix] ❌ Inscription ${req.params.id} REJECTED by ${req.user?.preferred_username}`);
        return res.json({ ok: true, action: 'rejected' });
      }

      // Approve = unlock back to pending
      await insRef.update({
        status: 'pending',
        lockedBy: null,
        lockedAt: null,
        approvedBy: req.user?.preferred_username || 'Direction',
        approvedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log(`[Auralix] ✅ Inscription ${req.params.id} APPROVED by ${req.user?.preferred_username}`);
      res.json({ ok: true, action: 'approved' });
    } catch (e) {
      console.error('[Auralix] Approve error:', e);
      res.status(500).json({ error: e.message });
    }
  });

  return router;
};
