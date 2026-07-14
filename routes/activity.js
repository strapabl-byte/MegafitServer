const express = require('express');
const { verifyAzureToken } = require('../middleware/auth');
const { logActivity, userFromReq } = require('../services/activity-logger');

module.exports = function (deps) {
  const router = express.Router();
  const { db } = deps;

  // ── In-memory cache: avoid hitting Firestore on every 30s dashboard poll ──
  const ACTIVITY_TTL_MS = 5 * 60 * 1000; // 5 minutes
  let activityCache = {};  // key: gymId → { data, ts }

  // GET /api/activity/logs
  router.get('/api/activity/logs', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'all' } = req.query;
      const now = Date.now();
      const cached = activityCache[gymId];

      // ✅ Serve from cache if fresh — zero Firestore reads
      if (cached && now - cached.ts < ACTIVITY_TTL_MS) {
        console.log(`⚡ [CACHE HIT] activity/logs (${gymId}) — ${Math.round((now - cached.ts)/1000)}s old`);
        return res.json(cached.data);
      }

      // 🌐 Cache miss — fetch from Firestore and store result
      console.log(`🌐 [CACHE MISS] activity/logs (${gymId}) — fetching from Firestore`);
      let query = db.collection('manager_activity_logs')
                    .orderBy('createdAt', 'desc')
                    .limit(50);

      if (gymId && gymId !== 'all') {
        query = query.where('gymId', '==', gymId);
      }

      const snap = await query.get();
      const logs = snap.docs.map(doc => {
        const data = doc.data();
        let timeLabel = '';
        if (data.createdAt) {
          const date = data.createdAt.toDate();
          timeLabel = date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
        }
        return {
          id: doc.id,
          time: timeLabel,
          action: data.action || 'Unknown action',
          club: data.club || { id: 'system', name: 'System', color: '#999' },
          user: data.userName || 'System'
        };
      });

      activityCache[gymId] = { data: logs, ts: now };
      res.json(logs);
    } catch (err) {
      console.error('Audit Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch logs' });
    }
  });

  // GET /api/door/history/:gymId
  router.get('/api/door/history/:gymId', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.params;
      const { date, startDate, endDate, name, limit } = req.query;
      const { lc } = deps;
      if (!lc) return res.status(500).json({ error: 'Local cache not initialized' });

      // Fetch entries directly from SQLite (Zero Firebase reads)
      const options = {
        date,
        startDate,
        endDate,
        name,
        limit: limit ? parseInt(limit, 10) : 1000
      };
      
      const entries = lc.getEntries(gymId, options); 
      res.json(entries);
    } catch (err) {
      console.error('Door History Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch door history' });
    }
  });

  // ── POST /public/activity/pwa-log ─────────────────────────────────────────
  // Lightweight activity beacon for the Inscription PWA.
  // Called fire-and-forget from the PWA whenever a commercial/manager performs
  // an action (select action, submit inscription, pay rest, extension, etc.)
  // Logs into the same 'manager_activity_logs' Firestore collection so these
  // activities appear in the Super Admin Command Center.
  // ──────────────────────────────────────────────────────────────────────────
  const GYM_CLUBS = {
    dokarat: { id: 'dokarat', name: 'Doukkarate', color: '#10b981' },
    marjane: { id: 'marjane', name: 'Saïss',      color: '#3b82f6' },
    casa1:   { id: 'casa1',   name: 'Casa Anfa',   color: '#f59e0b' },
    casa2:   { id: 'casa2',   name: 'Casa Lady',   color: '#ec4899' },
  };

  router.post('/public/activity/pwa-log', async (req, res) => {
    try {
      const {
        action,        // e.g. 'Nouvelle inscription soumise'
        page,          // e.g. 'Inscription', 'Payer Reste', 'Extension'
        gymId,         // e.g. 'dokarat'
        managerEmail,  // Azure email of the logged-in manager
        managerName,   // Display name
        commercialName,// QR-authenticated commercial
        memberName,    // Member being processed (optional)
        buttonClicked, // e.g. 'SOUMETTRE', 'PAYER', 'VALIDER' (optional)
      } = req.body;

      if (!action || !gymId) {
        return res.status(400).json({ error: 'action and gymId required' });
      }

      const club = GYM_CLUBS[gymId] || { id: gymId, name: gymId, color: '#999' };

      const payload = {
        action,
        page: page || 'Inscription PWA',
        gymId,
        club,
        userId: 'pwa_inscription',
        userName: commercialName || managerName || 'Commercial PWA',
        userEmail: (managerEmail || '').toLowerCase(),
        userRole: 'manager',
        path: '/public/inscriptions',
        method: 'POST',
        source: 'inscription_pwa',
        commercialName: commercialName || null,
        managerName: managerName || null,
        memberName: memberName || null,
        buttonClicked: buttonClicked || null,
        createdAt: deps.admin.firestore.FieldValue.serverTimestamp(),
      };

      // Fire-and-forget — don't block the PWA
      db.collection('manager_activity_logs').add(payload).catch(err => {
        console.error('[PWA-Log] Failed to write activity:', err.message);
      });

      // Invalidate activity cache so the dashboard sees the new entry sooner
      activityCache = {};

      res.json({ ok: true });
    } catch (err) {
      console.error('[PWA-Log] Error:', err);
      res.status(500).json({ error: 'Failed to log activity' });
    }
  });

  // ── POST /api/activity/track ──────────────────────────────────────────────
  // Page-visit beacon fired by the dashboard on every route change. Records
  // WHO (admin/manager/RH…) viewed WHICH page — the "which page he visited"
  // half of the audit trail (the auditLogger only catches mutations, never GETs).
  router.post('/api/activity/track', verifyAzureToken, (req, res) => {
    try {
      const { page, path, gymId } = req.body || {};
      if (!page) return res.status(400).json({ error: 'page required' });
      logActivity(deps, {
        action: `A consulté « ${String(page).slice(0, 60)} »`,
        page: String(page).slice(0, 60),
        gymId: gymId || req.assignedGyms?.[0] || 'system',
        method: 'VIEW',
        source: 'page_visit',
        user: userFromReq(req, path),
      });
      activityCache = {};
      res.json({ ok: true });
    } catch (err) {
      console.error('[activity/track] Error:', err.message);
      res.status(500).json({ error: 'Failed to track page' });
    }
  });

  return router;
};

