'use strict';
// routes/config.js — Public pass/status + Inscription form config + Chat

const { Router } = require('express');
const { verifyAzureToken } = require('../middleware/auth');

const GYM_IDS = ['dokarat', 'marjane', 'casa1', 'casa2'];

const DEFAULT_SUBSCRIPTION_GROUPS = [
  { label: 'COURTE DUREE', options: [{ name: '7 JOURS', price: 0, note: 'Accès 7 jours' }, { name: '15 JOURS', price: 800, note: 'Accès 15 jours' }] },
  { label: '1 MOIS', options: [{ name: '1 MOIS LOCAL', price: 1000, note: 'Accès local uniquement' }, { name: '1 MOIS LOCAL KIDS', price: 800, note: 'Enfants — accès local' }, { name: '1 MOIS MULTI', price: 1000, note: 'Multiclub — tous les 4 Gyms Megafit' }, { name: '1 MOIS MULTI CASA', price: 1200, note: 'Multiclub Casablanca' }] },
  { label: '3 MOIS', options: [{ name: '3 MOIS LOCAL', price: 0, note: 'Accès local uniquement' }, { name: '3 MOIS MULTI FES', price: 0, note: 'Multiclub Fès' }, { name: '3 MOIS CASA', price: 2200, note: 'Casablanca' }, { name: '3 MOIS KIDS', price: 2200, note: 'Enfants' }] },
  { label: '6 MOIS', options: [{ name: '6 MOIS MULTI', price: 5000, note: 'Multiclub — tous les 4 Gyms Megafit' }, { name: '6 MOIS KIDS', price: 6000, note: 'Enfants' }] },
  { label: '12 MOIS', options: [{ name: '12 MOIS LOCAL - 4000', price: 0, note: 'Accès local' }, { name: '12 MOIS - MULTI 5250', price: 0, note: 'Multiclub' }, { name: '12 MOIS AVEC ASSURANCE MEGA KIDS', price: 0, note: 'Enfants' }, { name: '12 MOIS OUVERTURE CASA-LADY ANFA', price: 0, note: 'Ouverture Anfa' }, { name: '12 MOIS OUVERTURE CASA-LADY ANFA + 10 SEANCES PILATES', price: 0, note: 'Lady Anfa + Pilates' }] },
  { label: '18 MOIS', options: [{ name: '18 MOIS LOCAL', price: 5500, note: 'Accès local' }, { name: '18 MOIS MULTI', price: 6500, note: 'Multiclub' }] },
  { label: '24 MOIS', options: [{ name: '24 MOIS - BLACK FRIDAY LOCAL', price: 0, note: 'Black Friday local' }, { name: '24 MOIS - BLACK FRIDAY MULTI', price: 0, note: 'Black Friday multiclub' }, { name: '24 MOIS AVEC ASSURANCE MEGA KIDS', price: 0, note: 'Enfants' }, { name: '24 MOIS OUVERTURE CASA-ANFA', price: 8900, note: 'Ouverture Anfa' }, { name: '24 MOIS OUVERTURE CASA-LADY ANFA', price: 6900, note: 'Ouverture Lady Anfa' }, { name: '24 MOIS OUVERTURE CASA-LADY ANFA + 10 SEANCES PILATES', price: 7900, note: 'Lady Anfa + Pilates' }, { name: '24 MOIS OUVERTURE SAISS MARJANE FES', price: 7900, note: 'Multiclub Fès' }, { name: '24 MOIS OUVERTURE SAISS MARJANE FES LOCAL', price: 6900, note: 'Fès local' }, { name: 'UPGRADE 24 MOIS OUVERTURE CASA-LADY ANFA', price: 0, note: 'Upgrade Lady Anfa' }] },
  { label: 'SAINT VALENTIN', options: [{ name: '1 AN S/V', price: 0, note: 'Offre Saint Valentin 1 an' }, { name: '2 ANS S/V', price: 0, note: 'Offre Saint Valentin 2 ans' }] },
  { label: 'ENTREES / CARNETS', options: [{ name: 'ENTREE JOURNALIER', price: 0, note: 'Séance unique' }, { name: '10 ENTREES', price: 0, note: 'Carnet 10' }, { name: '25 ENTREES', price: 1750, note: 'Carnet 25' }, { name: '30 ENTREES', price: 1800, note: 'Carnet 30' }, { name: '50 ENTREES', price: 2000, note: 'Carnet 50' }, { name: '25 TICKETS ENTREE JOURNALIERS CASA', price: 2500, note: 'Casa 25 tickets' }, { name: '50 TICKETS ENTREE JOURNALIERS CASA', price: 4500, note: 'Casa 50 tickets' }] },
  { label: 'CONVENTIONS', options: [{ name: 'CONVENTION CDGAPR', price: 0 }, { name: 'CONVENTION ATT.IJARI', price: 0 }, { name: 'CONVENTION BANQUE POPULAIRE', price: 0 }, { name: 'CONVENTION MARKET SOLUTION', price: 0 }, { name: 'CONVENTION CREDIT AGRICOL', price: 0 }] },
  { label: 'OFFRES / PROMOS', options: [{ name: 'OFFRE FAMILLE ASS', price: 0 }, { name: 'OFFRE 12 MOIS ETE FES LOCAL', price: 0 }, { name: 'PROMO 12 MOIS AVEC ASSURANCE', price: 0 }, { name: 'PROMO NOEL 12 MOIS CASA-ANFA', price: 0 }, { name: 'PROMO NOEL 24 MOIS CASA-ANFA', price: 0 }, { name: 'OFFERT PAR LA DIRECTION', price: 0 }, { name: 'OFFERT PAR LA DIRECTION KIDS', price: 0 }] },
  { label: 'TRANSFERTS / AUTRES', options: [{ name: 'TRANSFERT ABO', price: 0 }, { name: 'TRANSFERT OPTION', price: 0 }, { name: 'TRANSFERT PREMIUM', price: 0 }, { name: 'ACCES MULTI FES', price: 0 }] },
];

const defaultGymConfig = (gymId) => ({
  gymId,
  gymName: { dokarat: 'MEGAFIT DOKKARAT', marjane: 'MEGAFIT SAISS', casa1: 'MEGAFIT ANFA', casa2: 'MEGAFIT LADY ANFA' }[gymId] || 'MEGA FIT',
  registrationFee: 3000,
  isOpen: true,
  subscriptionGroups: DEFAULT_SUBSCRIPTION_GROUPS,
});

module.exports = function configRouter({ db, admin }) {
  const router = Router();

  function daysLeft(expiresOn) {
    if (!expiresOn) return null;
    const t   = new Date(); t.setHours(0, 0, 0, 0);
    const exp = new Date(expiresOn + 'T00:00:00');
    return Math.floor((exp - t) / 86400000);
  }

  // ── GET /public/pass/:token ───────────────────────────────────────────────
  router.get('/public/pass/:token', async (req, res) => {
    try {
      const snap = await db.collection('members').where('qrToken', '==', req.params.token).limit(1).get();
      if (snap.empty) return res.status(404).json({ error: 'Pass not found' });
      const docSnap = snap.docs[0];
      const data    = docSnap.data();
      const dLeft   = daysLeft(data.expiresOn);
      if (data.status?.active === false || (dLeft !== null && dLeft < 0)) return res.status(403).json({ error: 'Inactive membership' });
      await docSnap.ref.update({ qrToken: admin.firestore.FieldValue.delete() });
      await db.collection('access_logs').add({ memberId: docSnap.id, usedAt: admin.firestore.FieldValue.serverTimestamp(), type: 'qr' });
      const firebaseCustomToken = await admin.auth().createCustomToken(docSnap.id);
      res.json({ ok: true, firebaseCustomToken, member: { id: docSnap.id, fullName: data.fullName, expiresOn: data.expiresOn, status: { daysLeft: dLeft, active: true } } });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  // ── GET /public/member-status/:memberId ───────────────────────────────────
  router.get('/public/member-status/:memberId', async (req, res) => {
    try {
      const doc = await db.collection('members').doc(req.params.memberId).get();
      if (!doc.exists) return res.status(404).json({ ok: false, status: 'not_found' });
      const data    = doc.data();
      const dLeft   = daysLeft(data.expiresOn);
      const isActive = data.status?.active !== false && (dLeft === null || dLeft >= 0);
      res.json({ ok: true, memberId: req.params.memberId, status: isActive ? 'active' : 'inactive', daysLeft: dLeft });
    } catch (err) { res.status(500).json({ error: 'Status endpoint error' }); }
  });

  // ── POST /api/chat ────────────────────────────────────────────────────────
  router.post('/api/chat', verifyAzureToken, async (req, res) => {
    try {
      const { messages } = req.body;
      const GROQ_API_KEY = process.env.GROQ_API_KEY;
      if (!GROQ_API_KEY) return res.status(500).json({ error: 'Missing API Key' });
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages, model: 'llama-3.3-70b-versatile', temperature: 0.6, max_tokens: 300 }),
      });
      res.json(await response.json());
    } catch { res.status(500).json({ error: 'AI Proxy failed' }); }
  });

  // ── GET /public/inscription-config ────────────────────────────────────────
  router.get('/public/inscription-config', async (req, res) => {
    try {
      const gymId   = req.query.gymId || 'dokarat';
      const defaults = defaultGymConfig(gymId);
      try {
        const doc = await db.collection('config').doc(`inscription-${gymId}`).get();
        if (!doc.exists) return res.json(defaults);
        const merged = { ...defaults, ...doc.data() };
        if (!merged.gymName || merged.gymName === 'MEGA FIT') merged.gymName = defaults.gymName;
        return res.json(merged);
      } catch (firestoreErr) {
        console.warn(`inscription-config fallback for ${gymId}:`, firestoreErr.message);
        return res.json(defaults);
      }
    } catch (err) { res.status(500).json({ error: 'Could not load inscription config' }); }
  });

  // ── POST /api/inscription-config ──────────────────────────────────────────
  router.post('/api/inscription-config', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, gymName, registrationFee, isOpen, subscriptionGroups } = req.body;
      if (!gymId || !GYM_IDS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });
      if (!req.hasAccessToGym(gymId)) return res.status(403).json({ error: 'Access Denied' });
      await db.collection('config').doc(`inscription-${gymId}`).set({ gymId, gymName, registrationFee, isOpen, subscriptionGroups, updatedAt: new Date().toISOString() }, { merge: true });
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Could not save inscription config' }); }
  });

  // ── GET /api/inscription-configs ──────────────────────────────────────────
  router.get('/api/inscription-configs', verifyAzureToken, async (req, res) => {
    try {
      const allowed = GYM_IDS.filter(id => req.hasAccessToGym(id));
      const configs = await Promise.all(allowed.map(async (gymId) => {
        const doc = await db.collection('config').doc(`inscription-${gymId}`).get();
        return { ...defaultGymConfig(gymId), ...(doc.exists ? doc.data() : {}) };
      }));
      res.json(configs);
    } catch (err) { res.status(500).json({ error: 'Could not load configs' }); }
  });

  return router;
};
