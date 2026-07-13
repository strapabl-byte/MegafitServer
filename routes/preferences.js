'use strict';
// routes/preferences.js — per-user UI preferences (theme, day/night, performance),
// so each staff member (manager / RH / performance manager / super admin) keeps
// their own view of the platform across devices and browsers.
// Keyed by the Azure identity (oid) resolved from the verified token.

const { Router } = require('express');
const { verifyAzureToken } = require('../middleware/auth');

module.exports = function preferencesRouter({ db, admin }) {
  const router = Router();

  const keyOf = (req) => req.user?.oid || (req.user?.preferred_username || req.user?.email || '').toLowerCase() || null;
  const roleOf = (req) => req.isAdmin ? 'admin' : (req.isRH ? 'rh' : (req.isPerfManager ? 'performance_manager' : 'manager'));

  // Whitelist + type-check — never trust the client blob.
  const clean = (b = {}) => {
    const out = {};
    if (typeof b.theme === 'string') out.theme = b.theme.slice(0, 40);
    if (typeof b.dayMode === 'boolean') out.dayMode = b.dayMode;
    if (typeof b.dayModeAuto === 'boolean') out.dayModeAuto = b.dayModeAuto;
    if (typeof b.liteMode === 'boolean') out.liteMode = b.liteMode;
    return out;
  };

  // GET /api/preferences → { preferences: {...} | null }
  router.get('/api/preferences', verifyAzureToken, async (req, res) => {
    try {
      const id = keyOf(req);
      if (!id) return res.json({ preferences: null });
      const doc = await db.collection('user_preferences').doc(id).get();
      res.json({ preferences: doc.exists ? doc.data() : null });
    } catch (e) {
      console.error('[prefs] load error:', e.message);
      res.status(500).json({ error: 'prefs_load_failed' });
    }
  });

  // PUT /api/preferences  body: { theme, dayMode, dayModeAuto, liteMode }
  router.put('/api/preferences', verifyAzureToken, async (req, res) => {
    try {
      const id = keyOf(req);
      if (!id) return res.status(400).json({ error: 'no_identity' });
      const prefs = clean(req.body);
      await db.collection('user_preferences').doc(id).set({
        ...prefs,
        email: (req.user?.preferred_username || req.user?.email || '').toLowerCase() || null,
        role: roleOf(req),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
      res.json({ ok: true });
    } catch (e) {
      console.error('[prefs] save error:', e.message);
      res.status(500).json({ error: 'prefs_save_failed' });
    }
  });

  return router;
};
