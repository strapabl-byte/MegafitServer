'use strict';
// routes/commercials.js

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function commercialsRouter({ db, admin }) {
  const router = Router();

  // GET /api/commercials?gymId=dokarat
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat' } = req.query;
      const snap = await db.collection('gym_commercials').where('gymId', '==', gymId).get();
      const commercials = snap.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      res.json({ ok: true, commercials });
    } catch (err) {
      console.error('GET /api/commercials error:', err);
      res.status(500).json({ error: 'Failed to fetch commercials' });
    }
  });

  // POST /api/commercials
  router.post('/', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, name } = req.body;
      if (!gymId || !name) return res.status(400).json({ error: 'gymId and name required' });
      const docRef = await db.collection('gym_commercials').add({ gymId, name: name.trim().toUpperCase(), createdAt: admin.firestore.FieldValue.serverTimestamp() });
      res.json({ ok: true, id: docRef.id, name: name.trim().toUpperCase() });
    } catch (err) {
      console.error('POST /api/commercials error:', err);
      res.status(500).json({ error: 'Failed to add commercial' });
    }
  });

  // DELETE /api/commercials/:id
  router.delete('/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('gym_commercials').doc(req.params.id).delete();
      res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /api/commercials error:', err);
      res.status(500).json({ error: 'Failed to delete commercial' });
    }
  });

  return router;
};
