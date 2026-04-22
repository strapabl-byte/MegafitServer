const express = require('express');
const { verifyAzureToken } = require('../middleware/auth');

module.exports = function (deps) {
  const router = express.Router();
  const { db } = deps;

  // GET /api/activity/logs
  router.get('/activity/logs', verifyAzureToken, async (req, res) => {
    try {
      const { gymId } = req.query; // 'all' or specific
      
      let query = db.collection('manager_activity_logs')
                    .orderBy('createdAt', 'desc')
                    .limit(50);
                    
      if (gymId && gymId !== 'all') {
        const clubsMap = {
            'marjane': 'Marjane',
            'dokarat': 'Dokarat',
            'casa1': 'Casa 1',
            'casa2': 'Casa 2'
        };
        // Some flexibility for gymId values
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

      res.json(logs);
    } catch (err) {
      console.error('Audit Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch logs' });
    }
  });

  return router;
};
