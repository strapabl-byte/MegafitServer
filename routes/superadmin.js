'use strict';
// routes/superadmin.js — Super Admin Command Center API
// Powers the dashboard home page intelligence panels.
// ALL endpoints require Azure AD token + Admin role.

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function superadminRouter({ db, admin, lc }) {
  const router = Router();

  const GYM_NAMES = {
    dokarat: 'Fès Doukkarate',
    marjane: 'Fès Saïss',
    casa1:   'Casa Anfa',
    casa2:   'Casa Lady',
  };
  const GYM_COLORS = {
    dokarat: '#10b981',
    marjane: '#3b82f6',
    casa1:   '#f59e0b',
    casa2:   '#ec4899',
    system:  '#999999',
  };
  const ALL_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];

  // ── Morocco time helper ───────────────────────────────────────────────────
  function todayDate() {
    const moroccoHour = (new Date().getUTCHours() + 1) % 24;
    const d = new Date(Date.now() + 3600000);
    if (moroccoHour < 6) d.setUTCDate(d.getUTCDate() - 1);
    return d.toISOString().slice(0, 10);
  }

  function dateRange(days) {
    const dates = [];
    const moroccoNow = new Date(Date.now() + 3600000);
    const moroccoHour = moroccoNow.getUTCHours();
    const start = new Date(moroccoNow);
    if (moroccoHour < 6) start.setUTCDate(start.getUTCDate() - 1);
    for (let i = 0; i < days; i++) {
      const d = new Date(start);
      d.setUTCDate(d.getUTCDate() - i);
      dates.push(d.toISOString().slice(0, 10));
    }
    return dates;
  }

  function thisMonthDates() {
    const now = new Date(Date.now() + 3600000);
    const year = now.getUTCFullYear();
    const month = now.getUTCMonth();
    const daysInMonth = now.getUTCDate();
    const dates = [];
    for (let d = 1; d <= daysInMonth; d++) {
      const dd = new Date(Date.UTC(year, month, d));
      dates.push(dd.toISOString().slice(0, 10));
    }
    return dates;
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 1. GET /api/superadmin/activity-feed
  //    Enhanced manager activity logs with page, role, email
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/activity-feed', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, userEmail, role, limit: rawLimit } = req.query;
      const limitNum = Math.min(parseInt(rawLimit) || 100, 200);

      let query = db.collection('manager_activity_logs')
                    .orderBy('createdAt', 'desc')
                    .limit(limitNum);

      if (gymId && gymId !== 'all') {
        query = query.where('gymId', '==', gymId);
      }

      const snap = await query.get();
      let logs = snap.docs.map(doc => {
        const data = doc.data();
        let timeLabel = '';
        let dateLabel = '';
        if (data.createdAt) {
          const date = data.createdAt.toDate();
          timeLabel = date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
          dateLabel = date.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
        }

        // Derive page name — prefer explicit field (set by PWA logger), fall back to path-based
        let page = data.page || 'Système';
        if (!data.page) {
          const path = data.path || '';
          if (path.includes('/register'))       page = 'Registre';
          else if (path.includes('/payments'))  page = 'Paiements';
          else if (path.includes('/inscriptions')) page = 'Inscriptions';
          else if (path.includes('/members'))   page = 'Membres';
          else if (path.includes('/courses'))   page = 'Cours';
          else if (path.includes('/coaches'))   page = 'Coachs';
          else if (path.includes('/sales'))     page = 'Commerciaux';
          else if (path.includes('/relance'))   page = 'Relance';
          else if (path.includes('/scan'))      page = 'Scanner';
          else if (path.includes('/push'))      page = 'Notifications';
          else if (path.includes('/auralix'))   page = 'Auralix';
          else if (path.includes('/email'))     page = 'Email';
          else if (path.includes('/config'))    page = 'Configuration';
        }

        // Determine user role
        let userRole = data.userRole || 'unknown';
        const email = (data.userEmail || '').toLowerCase();
        // PWA inscription source gets its own role tag
        if (data.source === 'inscription_pwa') {
          userRole = 'commercial_pwa';
        } else if (email.includes('megafitrh'))          userRole = 'rh';
        else if (email.includes('performance'))   userRole = 'performance_manager';
        else if (email.includes('megafitsaiss') || email.includes('megafitdokkarat') ||
                 email.includes('megafitanfa') || email.includes('megafitlady'))
                                                  userRole = 'manager';
        else if (data.userId !== 'system_id')     userRole = 'admin';

        return {
          id: doc.id,
          time: timeLabel,
          date: dateLabel,
          action: data.action || 'Unknown action',
          page,
          method: data.method || '',
          club: data.club || { id: 'system', name: 'System', color: '#999' },
          user: data.userName || 'System',
          userEmail: data.userEmail || email || '',
          userRole,
          gymId: data.gymId || 'system',
        };
      });

      // Client-side filters for fields not indexed in Firestore
      if (userEmail) {
        logs = logs.filter(l => l.userEmail.toLowerCase().includes(userEmail.toLowerCase()));
      }
      if (role && role !== 'all') {
        logs = logs.filter(l => l.userRole === role);
      }

      res.json({ ok: true, logs, count: logs.length });
    } catch (err) {
      console.error('[SuperAdmin] Activity feed error:', err);
      res.status(500).json({ error: 'Failed to fetch activity feed' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 2. GET /api/superadmin/inscriptions-summary
  //    Pipeline: pending, locked, approved, recent
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/inscriptions-summary', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId } = req.query;

      // Fetch all non-deleted inscriptions
      let query = db.collection('pending_members').where('source', '==', 'web');
      if (gymId && gymId !== 'all') {
        query = query.where('gymId', '==', gymId);
      }

      const snap = await query.get();
      const all = snap.docs.map(d => {
        const data = d.data();
        let createdAtStr = '';
        if (data.createdAt?._seconds) {
          createdAtStr = new Date(data.createdAt._seconds * 1000).toISOString();
        }
        let approvedAtStr = '';
        if (data.approvedAt?._seconds) {
          approvedAtStr = new Date(data.approvedAt._seconds * 1000).toISOString();
        }

        return {
          id: d.id,
          prenom: data.prenom || '',
          nom: data.nom || '',
          fullName: `${data.prenom || ''} ${data.nom || ''}`.trim(),
          telephone: data.telephone || '',
          gymId: data.gymId || '',
          gymName: GYM_NAMES[data.gymId] || data.gymId || '',
          subscriptionName: data.subscriptionName || '',
          totalDue: data.totals?.total || 0,
          totalPaid: data.totals?.paid || 0,
          balance: data.totals?.balance || 0,
          status: data.status || 'pending',
          lockedBy: data.lockedBy || '',
          approvedBy: data.approvedBy || '',
          contractNumber: data.contractNumber || '',
          commercial: data.commercial || data.submittedBy || '',
          memberId: data.memberId || null,
          createdAt: createdAtStr,
          approvedAt: approvedAtStr,
          pdfUrl: data.pdfUrl || null,
        };
      }).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

      // Summary counts
      const pending  = all.filter(i => i.status === 'pending').length;
      const locked   = all.filter(i => i.status === 'locked').length;
      const awaitingPayment = all.filter(i => i.status === 'awaiting_payment').length;
      const converted = all.filter(i => i.status === 'converted').length;

      res.json({
        ok: true,
        summary: { pending, locked, awaitingPayment, converted, total: all.length },
        inscriptions: all.slice(0, 100), // Limit to 100 most recent
      });
    } catch (err) {
      console.error('[SuperAdmin] Inscriptions summary error:', err);
      res.status(500).json({ error: 'Failed to fetch inscriptions summary' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 3. GET /api/superadmin/payment-history
  //    Revenue feed from SQLite register_cache (zero Firebase reads)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/payment-history', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      const period = req.query.period || 'today';
      const gymId  = req.query.gymId;
      
      let dates;
      if (period === 'today')      dates = [todayDate()];
      else if (period === 'week')  dates = dateRange(7);
      else if (period === 'month') dates = thisMonthDates();
      else if (period === 'range' && req.query.days) dates = dateRange(Math.min(parseInt(req.query.days), 90));
      else dates = [todayDate()];

      const ph = dates.map(() => '?').join(',');

      // Per-gym revenue summary
      const gymSummaries = ALL_GYMS.map(gid => {
        try {
          const rows = lc.db.prepare(
            `SELECT COALESCE(CAST(tpe AS REAL),0) AS tpe,
                    COALESCE(CAST(espece AS REAL),0) AS espece,
                    COALESCE(CAST(virement AS REAL),0) AS virement,
                    COALESCE(CAST(cheque AS REAL),0) AS cheque
             FROM register_cache WHERE gym_id=? AND date IN (${ph})`
          ).all(gid, ...dates);

          const espece   = Math.round(rows.reduce((s, r) => s + (r.espece || 0), 0));
          const tpe      = Math.round(rows.reduce((s, r) => s + (r.tpe || 0), 0));
          const virement = Math.round(rows.reduce((s, r) => s + (r.virement || 0), 0));
          const cheque   = Math.round(rows.reduce((s, r) => s + (r.cheque || 0), 0));
          const revenue  = espece + tpe + virement + cheque;

          return {
            id: gid,
            name: GYM_NAMES[gid],
            color: GYM_COLORS[gid],
            revenue, espece, tpe, virement, cheque,
            transactions: rows.length,
          };
        } catch (e) {
          return { id: gid, name: GYM_NAMES[gid], color: GYM_COLORS[gid], revenue: 0, espece: 0, tpe: 0, virement: 0, cheque: 0, transactions: 0 };
        }
      });

      // Transaction list
      let gymFilter = '';
      let params = [...dates];
      if (gymId && gymId !== 'all') {
        gymFilter = ' AND gym_id=?';
        params.push(gymId);
      }

      const transactions = lc.db.prepare(
        `SELECT id, gym_id, date, nom, abonnement, commercial, contrat, cin,
                ROUND(COALESCE(CAST(tpe AS REAL),0)+COALESCE(CAST(espece AS REAL),0)+COALESCE(CAST(virement AS REAL),0)+COALESCE(CAST(cheque AS REAL),0)) AS montant,
                COALESCE(CAST(tpe AS REAL),0) AS tpe, COALESCE(CAST(espece AS REAL),0) AS espece,
                COALESCE(CAST(virement AS REAL),0) AS virement, COALESCE(CAST(cheque AS REAL),0) AS cheque,
                COALESCE(CAST(reste AS REAL),0) AS reste, created_at
         FROM register_cache WHERE date IN (${ph})${gymFilter} ORDER BY created_at DESC, rowid DESC LIMIT 200`
      ).all(...params).filter(r => r.montant > 0).map(r => {
        const methods = [];
        if (r.tpe > 0)      methods.push('TPE');
        if (r.espece > 0)   methods.push('ESPÈCE');
        if (r.virement > 0) methods.push('VIREMENT');
        if (r.cheque > 0)   methods.push('CHÈQUE');
        return {
          ...r,
          gymName: GYM_NAMES[r.gym_id] || r.gym_id,
          gymColor: GYM_COLORS[r.gym_id] || '#999',
          method: methods.join(' + ') || '?',
        };
      });

      // Grand total
      const total = gymSummaries.reduce((s, g) => ({
        revenue: s.revenue + g.revenue,
        espece: s.espece + g.espece,
        tpe: s.tpe + g.tpe,
        virement: s.virement + g.virement,
        cheque: s.cheque + g.cheque,
      }), { revenue: 0, espece: 0, tpe: 0, virement: 0, cheque: 0 });

      res.json({ ok: true, gyms: gymSummaries, total, transactions, period });
    } catch (err) {
      console.error('[SuperAdmin] Payment history error:', err);
      res.status(500).json({ error: 'Failed to fetch payment history' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 4. GET /api/superadmin/entries-overview
  //    Entry/visit counts per gym from SQLite daily_stats
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/entries-overview', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      const days = Math.min(parseInt(req.query.days) || 7, 30);
      const dates = dateRange(days);
      const ph = dates.map(() => '?').join(',');

      const gyms = ALL_GYMS.map(gid => {
        const rows = lc.db.prepare(
          `SELECT date, count, raw_count FROM daily_stats WHERE gym_id=? AND date IN (${ph}) ORDER BY date ASC`
        ).all(gid, ...dates);

        const todayRow = rows.find(r => r.date === todayDate());
        const sparkline = dates.slice().reverse().map(d => {
          const r = rows.find(row => row.date === d);
          return { date: d, count: r?.count || 0, rawCount: r?.raw_count || 0 };
        });

        return {
          id: gid,
          name: GYM_NAMES[gid],
          color: GYM_COLORS[gid],
          todayCount: todayRow?.count || 0,
          todayRaw: todayRow?.raw_count || 0,
          weekTotal: rows.reduce((s, r) => s + (r.count || 0), 0),
          sparkline,
        };
      });

      res.json({ ok: true, gyms, today: todayDate() });
    } catch (err) {
      console.error('[SuperAdmin] Entries overview error:', err);
      res.status(500).json({ error: 'Failed to fetch entries overview' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 5. GET /api/superadmin/decaissements-feed
  //    All décaissements from SQLite
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/decaissements-feed', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      const { status, gymId } = req.query;

      let where = '1=1';
      const params = [];

      if (status && status !== 'all') {
        if (status === 'pending') {
          where += " AND (status = 'pending' OR status IS NULL)";
        } else {
          where += ' AND status = ?';
          params.push(status);
        }
      }
      if (gymId && gymId !== 'all') {
        where += ' AND gym_id = ?';
        params.push(gymId);
      }

      const rows = lc.db.prepare(
        `SELECT id, gym_id, date, montant, raison, commercial, signature, requested_by, status, created_at
         FROM decaissements_cache WHERE ${where} ORDER BY date DESC, rowid DESC LIMIT 100`
      ).all(...params);

      const decaissements = rows.map(r => ({
        ...r,
        requestedBy: r.requested_by,
        gymName: GYM_NAMES[r.gym_id] || r.gym_id,
        gymColor: GYM_COLORS[r.gym_id] || '#999',
        status: r.status || 'pending',
      }));

      // Summary counts
      const allRows = lc.db.prepare(
        `SELECT status FROM decaissements_cache`
      ).all();
      const pending  = allRows.filter(r => !r.status || r.status === 'pending').length;
      const approved = allRows.filter(r => r.status === 'approved').length;
      const rejected = allRows.filter(r => r.status === 'rejected').length;

      res.json({
        ok: true,
        summary: { pending, approved, rejected, total: allRows.length },
        decaissements,
      });
    } catch (err) {
      console.error('[SuperAdmin] Decaissements feed error:', err);
      res.status(500).json({ error: 'Failed to fetch decaissements feed' });
    }
  });

  return router;
};
