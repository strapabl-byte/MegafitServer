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

  function getDatesInRange(startDate, endDate) {
    const dates = [];
    const start = new Date(startDate);
    const end = new Date(endDate);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) return [];
    const diffTime = end.getTime() - start.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const limitDays = Math.max(0, Math.min(diffDays, 90));
    for (let i = 0; i <= limitDays; i++) {
      const d = new Date(start);
      d.setDate(d.getDate() + i);
      dates.push(d.toISOString().slice(0, 10));
    }
    return dates;
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 1. GET /api/superadmin/activity-feed
  //    Enhanced manager activity logs — reads from SQLite cache (zero Firebase reads)
  //    Accepts: gymId, role, startDate, endDate, limit
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/activity-feed', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, role, startDate, endDate, limit: rawLimit } = req.query;
      const limitNum = Math.min(parseInt(rawLimit) || 100, 500);

      // Try SQLite first (zero Firebase reads)
      const cachedCount = lc.getActivityLogsCount();
      if (cachedCount > 0) {
        const rows = lc.getActivityLogs({ gymId, role, startDate, endDate, limit: limitNum });
        const logs = rows.map(r => {
          let timeLabel = '';
          let dateLabel = '';
          if (r.created_at) {
            const d = new Date(r.created_at);
            timeLabel = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
            dateLabel = d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
          }
          return {
            id: r.id,
            time: timeLabel,
            date: dateLabel,
            action: r.action || 'Unknown action',
            page: r.page || 'Système',
            method: r.method || '',
            club: { id: r.club_id || 'system', name: r.club_name || 'System', color: r.club_color || '#999' },
            user: r.user_name || 'System',
            userEmail: r.user_email || '',
            userRole: r.user_role || 'unknown',
            gymId: r.gym_id || 'system',
            eventType: r.source || 'mutation',
          };
        });
        return res.json({ ok: true, logs, count: logs.length, source: 'sqlite' });
      }

      // Fallback: Firestore (only on first run before sync)
      let query = db.collection('manager_activity_logs')
                    .orderBy('createdAt', 'desc')
                    .limit(500);

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

        let userRole = data.userRole || 'unknown';
        const email = (data.userEmail || '').toLowerCase();
        if (data.source === 'inscription_pwa') userRole = 'commercial_pwa';
        else if (email.includes('megafitrh'))          userRole = 'rh';
        else if (email.includes('performance'))        userRole = 'performance_manager';
        else if (email.includes('megafitsaiss') || email.includes('megafitdokkarat') ||
                 email.includes('megafitanfa') || email.includes('megafitlady'))
                                                       userRole = 'manager';
        else if (data.userId !== 'system_id')          userRole = 'admin';

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
          eventType: data.source || 'mutation',
        };
      });

      // Client-side filters (fallback path only)
      if (gymId && gymId !== 'all') {
        logs = logs.filter(l => {
          const logGym = (l.gymId || '').toLowerCase();
          const clubId = (l.club?.id || '').toLowerCase();
          const target = gymId.toLowerCase();
          return logGym === target || clubId === target;
        });
      }
      if (role && role !== 'all') {
        logs = logs.filter(l => l.userRole === role);
      }
      logs = logs.slice(0, limitNum);

      res.json({ ok: true, logs, count: logs.length, source: 'firestore' });
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
      const { startDate, endDate, period, gymId } = req.query;
      
      let dates;
      if (startDate && endDate) {
        dates = getDatesInRange(startDate, endDate);
      } else {
        const activePeriod = period || 'today';
        if (activePeriod === 'today')      dates = [todayDate()];
        else if (activePeriod === 'yesterday') {
          const yest = new Date(Date.now() - 86400000 + 3600000);
          dates = [yest.toISOString().slice(0, 10)];
        }
        else if (activePeriod === 'week')  dates = dateRange(7);
        else if (activePeriod === 'month') dates = thisMonthDates();
        else if (activePeriod === 'range' && req.query.days) dates = dateRange(Math.min(parseInt(req.query.days), 90));
        else dates = [todayDate()];
      }

      if (!dates || dates.length === 0) dates = [todayDate()];

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

          const decsRows = lc.db.prepare(
            `SELECT COALESCE(CAST(montant AS REAL),0) AS montant, status
             FROM decaissements_cache WHERE gym_id=? AND date IN (${ph})`
          ).all(gid, ...dates);

          const espece   = Math.round(rows.reduce((s, r) => s + (r.espece || 0), 0));
          const tpe      = Math.round(rows.reduce((s, r) => s + (r.tpe || 0), 0));
          const virement = Math.round(rows.reduce((s, r) => s + (r.virement || 0), 0));
          const cheque   = Math.round(rows.reduce((s, r) => s + (r.cheque || 0), 0));
          const revenue  = espece + tpe + virement + cheque;
          const decaissement = Math.round(decsRows.filter(d => d.status !== 'rejected').reduce((s, r) => s + (r.montant || 0), 0));
          const netRevenue = revenue - decaissement;

          return {
            id: gid,
            name: GYM_NAMES[gid],
            color: GYM_COLORS[gid],
            revenue, espece, tpe, virement, cheque,
            decaissement, netRevenue,
            transactions: rows.length,
          };
        } catch (e) {
          return { id: gid, name: GYM_NAMES[gid], color: GYM_COLORS[gid], revenue: 0, decaissement: 0, netRevenue: 0, espece: 0, tpe: 0, virement: 0, cheque: 0, transactions: 0 };
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
        decaissement: s.decaissement + (g.decaissement || 0),
        netRevenue: s.netRevenue + (g.netRevenue || 0),
        espece: s.espece + g.espece,
        tpe: s.tpe + g.tpe,
        virement: s.virement + g.virement,
        cheque: s.cheque + g.cheque,
      }), { revenue: 0, decaissement: 0, netRevenue: 0, espece: 0, tpe: 0, virement: 0, cheque: 0 });

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

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 6. GET /api/superadmin/team-activity
  //    Aggregated user activity — reads from SQLite cache (zero Firebase reads)
  //    Accepts: gymId, role, startDate, endDate
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.get('/api/superadmin/team-activity', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, role, startDate, endDate } = req.query;
      const now = Date.now();
      const todayStr = todayDate();

      // Determine date range for query
      const queryStartDate = startDate || new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
      const queryEndDate = endDate || todayStr;

      // Try SQLite first
      const cachedCount = lc.getActivityLogsCount();
      let rawLogs;

      if (cachedCount > 0) {
        rawLogs = lc.getActivityLogs({ startDate: queryStartDate, endDate: queryEndDate, limit: 2000 });
        rawLogs = rawLogs.map(r => ({
          userEmail: r.user_email || '',
          userName: r.user_name || '',
          userRole: r.user_role || 'unknown',
          gymId: r.gym_id || 'system',
          action: r.action || '',
          page: r.page || 'Système',
          source: r.source === 'inscription_pwa' ? 'pwa' : 'dashboard',
          createdAt: r.created_at,
          date: r.date,
        }));
      } else {
        // Fallback: Firestore
        const sinceDate = new Date(queryStartDate);
        const snap = await db.collection('manager_activity_logs')
          .where('createdAt', '>=', sinceDate)
          .orderBy('createdAt', 'desc')
          .limit(1000)
          .get();

        rawLogs = snap.docs.map(doc => {
          const d = doc.data();
          const email = (d.userEmail || '').toLowerCase();
          const ts = d.createdAt?.toDate ? d.createdAt.toDate() : new Date();

          let userRole = d.userRole || 'unknown';
          if (d.source === 'inscription_pwa') userRole = 'commercial_pwa';
          else if (email.includes('megafitrh'))          userRole = 'rh';
          else if (email.includes('performance'))        userRole = 'performance_manager';
          else if (email.includes('megafitsaiss') || email.includes('megafitdokkarat') ||
                   email.includes('megafitanfa') || email.includes('megafitlady'))
                                                         userRole = 'manager';
          else if (d.userId !== 'system_id' && d.userId !== 'pwa_inscription') userRole = 'admin';

          let gid = d.gymId || 'system';
          if (gid === 'system' && email.includes('megafitsaiss'))     gid = 'marjane';
          if (gid === 'system' && email.includes('megafitdokkarat'))  gid = 'dokarat';
          if (gid === 'system' && email.includes('megafitanfa'))      gid = 'casa1';
          if (gid === 'system' && email.includes('megafitlady'))      gid = 'casa2';

          let page = d.page || 'Système';
          if (!d.page) {
            const path = d.path || '';
            if (path.includes('/register'))       page = 'Registre';
            else if (path.includes('/payments'))  page = 'Paiements';
            else if (path.includes('/inscriptions')) page = 'Inscriptions';
            else if (path.includes('/members'))   page = 'Membres';
            else if (path.includes('/courses'))   page = 'Cours';
            else if (path.includes('/relance'))   page = 'Relance';
          }

          return {
            userEmail: d.userEmail || email,
            userName: d.userName || d.commercialName || email.split('@')[0],
            userRole,
            gymId: gid,
            action: d.action || '',
            page,
            source: d.source === 'inscription_pwa' ? 'pwa' : 'dashboard',
            createdAt: ts.toISOString(),
            date: new Date(ts.getTime() + 3600000).toISOString().slice(0, 10),
          };
        });
      }

      // Aggregate by unique user email
      const userMap = {};
      rawLogs.forEach(d => {
        const email = (d.userEmail || '').toLowerCase().trim();
        if (!email || email === 'admin@local.dev') return;

        const ts = new Date(d.createdAt).getTime();
        const source = d.source;

        if (!userMap[email]) {
          userMap[email] = {
            email,
            name: d.userName,
            role: d.userRole,
            gymId: d.gymId,
            gymName: GYM_NAMES[d.gymId] || d.gymId,
            gymColor: GYM_COLORS[d.gymId] || '#999',
            lastSeen: ts,
            lastAction: d.action,
            lastPage: d.page,
            source,
            actionsToday: 0,
            actionsWeek: 0,
            sources: new Set(),
          };
        }

        const u = userMap[email];
        u.actionsWeek++;
        if (d.date === todayStr) u.actionsToday++;
        u.sources.add(source);

        if (ts > u.lastSeen) {
          u.lastSeen = ts;
          u.lastAction = d.action || u.lastAction;
          u.lastPage = d.page;
          u.name = d.userName || u.name;
          u.source = source;
          if (d.gymId !== 'system') {
            u.gymId = d.gymId;
            u.gymName = GYM_NAMES[d.gymId] || d.gymId;
            u.gymColor = GYM_COLORS[d.gymId] || '#999';
          }
        }
      });

      // Convert to array and compute relative times
      let users = Object.values(userMap).map(u => {
        const diffMs = now - u.lastSeen;
        const diffMin = Math.floor(diffMs / 60000);
        const diffH = Math.floor(diffMs / 3600000);
        const diffD = Math.floor(diffMs / 86400000);

        let lastSeenRelative;
        if (diffMin < 1) lastSeenRelative = 'À l\'instant';
        else if (diffMin < 60) lastSeenRelative = `Il y a ${diffMin} min`;
        else if (diffH < 24) lastSeenRelative = `Il y a ${diffH}h`;
        else if (diffD === 1) lastSeenRelative = 'Hier';
        else lastSeenRelative = `Il y a ${diffD}j`;

        const isOnline = diffMin <= 15;

        return {
          email: u.email,
          name: u.name,
          role: u.role,
          gymId: u.gymId,
          gymName: u.gymName,
          gymColor: u.gymColor,
          lastSeen: u.lastSeen ? new Date(u.lastSeen).toISOString() : null,
          lastSeenRelative,
          isOnline,
          actionsToday: u.actionsToday,
          actionsWeek: u.actionsWeek,
          lastAction: u.lastAction,
          lastPage: u.lastPage,
          source: u.source,
          sources: [...u.sources],
        };
      });

      // Post-query filters (gym + role)
      if (gymId && gymId !== 'all') {
        users = users.filter(u => u.gymId === gymId);
      }
      if (role && role !== 'all') {
        users = users.filter(u => u.role === role);
      }

      // Sort: online first, then by most recent activity
      users.sort((a, b) => {
        if (a.isOnline !== b.isOnline) return a.isOnline ? -1 : 1;
        return new Date(b.lastSeen) - new Date(a.lastSeen);
      });

      const summary = {
        totalUsers: users.length,
        onlineNow: users.filter(u => u.isOnline).length,
        activeToday: users.filter(u => u.actionsToday > 0).length,
      };

      res.json({ ok: true, users, summary });
    } catch (err) {
      console.error('[SuperAdmin] Team activity error:', err);
      res.status(500).json({ error: 'Failed to fetch team activity' });
    }
  });

  return router;
};
