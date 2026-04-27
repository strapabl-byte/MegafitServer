const express = require('express');
const { verifyAzureToken } = require('../middleware/auth');

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

  return router;
};

