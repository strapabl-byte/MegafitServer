'use strict';
// routes/inscriptions.js — public form submissions + admin dashboard management

const { Router } = require('express');
const crypto = require('crypto');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function inscriptionsRouter({ db, admin, lc, apiCache, uploadBase64ToStorage, invalidateCache }) {
  const router = Router();

  // ── GET /public/next-contract-number ──────────────────────────────────────
  // Read-only peek — does NOT increment the counter. Safe to call any time.
  // Used only for display purposes (e.g. admin previewing the next number).
  router.get('/public/next-contract-number', async (req, res) => {
    try {
      const doc = await db.collection('settings').doc('contractCounter').get();
      const num = doc.exists && doc.data().current ? doc.data().current + 1 : 15001;
      res.json({ contractNumber: num.toString().padStart(6, '0') });
    } catch {
      res.json({ contractNumber: '015001', fallback: true });
    }
  });

  // POST /public/generate-contract — REMOVED.
  // This route used to increment the counter without creating a real inscription,
  // causing contract numbers to be skipped on every refresh/preview.
  // Contract numbers are ONLY assigned atomically inside POST /public/inscriptions.

  // ── POST /public/inscriptions ─────────────────────────────────────────────
  router.post('/public/inscriptions', async (req, res) => {
    try {
      const data = req.body;
      const rawGymId = data.gymId || req.query.gymId || req.query.gym || 'dokarat';
      const gymMap = { dokkarat: 'dokarat', marjane: 'marjane', casa1: 'casa1', casa2: 'casa2' };
      const normalizedGymId = gymMap[rawGymId.toLowerCase().trim()] || rawGymId.toLowerCase().trim();
      let finalContractNumber = '000000';

      const result = await db.runTransaction(async (t) => {
        const counterRef = db.collection('settings').doc('contractCounter');
        const cSnap = await t.get(counterRef);
        let nextNum = 15000;
        if (!cSnap.exists) { t.set(counterRef, { current: nextNum }); }
        else { nextNum = cSnap.data().current + 1; t.update(counterRef, { current: nextNum }); }
        finalContractNumber = nextNum.toString().padStart(6, '0');
        const newDocRef = db.collection('pending_members').doc();
        t.set(newDocRef, { ...data, contractNumber: finalContractNumber, gymId: normalizedGymId, source: 'web', status: 'pending', createdAt: admin.firestore.FieldValue.serverTimestamp() });
        return { id: newDocRef.id };
      });

      console.log(`📝 Inscription N° ${finalContractNumber} — ${normalizedGymId}`);
      
      // ✅ MEGAEYE FAST SYNC: Send lightweight copy to local 1GB SQLite disk 
      lc.setPending({
        id: result.id, 
        gymId: normalizedGymId, 
        nom: data.nom, 
        prenom: data.prenom,
        subscriptionName: data.subscriptionName,
        totals: data.totals,
        createdAt: { _seconds: Math.floor(Date.now() / 1000) } 
      });

      invalidateCache(apiCache.inscriptions);
      res.json({ id: result.id, ok: true, contractNumber: finalContractNumber });
    } catch (err) {
      console.error('Public Inscription Error:', err);
      res.status(500).json({ error: 'Failed to submit inscription' });
    }
  });

  // ── GET /public/members/search ────────────────────────────────────────────
  router.get('/public/members/search', async (req, res) => {
    try {
      const q = (req.query.q || '').trim().toLowerCase();
      if (q.length < 2) return res.json([]);
      const snap = await db.collection('members').get();
      const matches = snap.docs
        .map(d => ({ id: d.id, ...d.data() }))
        .filter(m => (m.fullName || '').toLowerCase().includes(q) || (m.cin || '').toLowerCase().includes(q) || (m.phone || '').includes(q))
        .slice(0, 5)
        .map(m => ({
          id: m.id, fullName: m.fullName,
          nom: (m.fullName || '').split(' ').pop(), prenom: (m.fullName || '').split(' ')[0],
          cin: m.cin, phone: m.phone, email: m.email, birthday: m.birthday,
          adresse: m.adresse || m.address || '', ville: m.ville || m.city || '',
        }));
      res.json(matches);
    } catch (err) {
      console.error('Public Member Search Error:', err);
      res.status(500).json({ error: 'Failed to search members' });
    }
  });

  // ── GET /api/inscriptions ─────────────────────────────────────────────────
  router.get('/api/inscriptions', verifyAzureToken, async (req, res) => {
    try {
      const gymId = req.query.gymId;
      const key   = gymId || 'all';
      let query = db.collection('pending_members').where('source', '==', 'web').where('status', '==', 'pending');
      if (gymId) query = query.where('gymId', '==', gymId);

      const cached = apiCache.inscriptions[key];
      if (cached && Date.now() - cached.ts < 30000) return res.json(cached.data);

      const snap = await query.get();
      const data = snap.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
      apiCache.inscriptions[key] = { data, ts: Date.now() };
      res.json(data);
    } catch (err) {
      console.error('Inscriptions Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch pending inscriptions' });
    }
  });

  // ── PATCH /api/inscriptions/:id ───────────────────────────────────────────
  router.patch('/api/inscriptions/:id', verifyAzureToken, async (req, res) => {
    try {
      const updateData = { ...req.body, updatedAt: admin.firestore.FieldValue.serverTimestamp() };
      await db.collection('pending_members').doc(req.params.id).update(updateData);
      if (req.body.memberId) {
        const orphans = await db.collection('payments').where('inscriptionId', '==', req.params.id).get();
        if (!orphans.empty) {
          const batch = db.batch();
          orphans.forEach(p => batch.update(p.ref, { memberId: req.body.memberId }));
          await batch.commit();
        }
      }
      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to update inscription' }); }
  });

  // ── PATCH /api/inscriptions/:id/set-pdf ──────────────────────────────────
  router.patch('/api/inscriptions/:id/set-pdf', async (req, res) => {
    try {
      const { pdfUrl } = req.body;
      if (!pdfUrl) return res.status(400).json({ error: 'pdfUrl required' });
      await db.collection('pending_members').doc(req.params.id).update({ pdfUrl, pdfUploadedAt: admin.firestore.FieldValue.serverTimestamp() });
      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true });
    } catch (err) {
      console.error('Set PDF URL error:', err);
      res.status(500).json({ error: 'Failed to save PDF URL' });
    }
  });

  // ── POST /api/inscriptions/:id/confirm ────────────────────────────────────
  router.post('/api/inscriptions/:id/confirm', verifyAzureToken, async (req, res) => {
    try {
      const insRef = db.collection('pending_members').doc(req.params.id);
      const insDoc = await insRef.get();
      if (!insDoc.exists) return res.status(404).json({ error: 'Inscription not found' });
      const ins = insDoc.data();
      if (ins.status === 'converted') return res.status(409).json({ error: 'Inscription already confirmed' });
      if (ins.memberId) return res.status(409).json({ error: 'Member already created for this inscription' });

      const gymId = ins.gymId || 'dokarat';
      const sName = (ins.subscriptionName || '').toLowerCase();
      let plan = 'Monthly';
      if (sName.includes('an') || sName.includes('anu')) plan = 'Annual';
      else if (sName.includes('trim') || sName.includes('3 mois')) plan = 'Quarterly';
      else if (sName.includes('sem') || sName.includes('6 mois')) plan = 'Semi-Annual';

      // Only link if explicitly selected via autocomplete in the form
      let existingMember = null;
      if (ins.selectedMemberId) {
        const doc = await db.collection('members').doc(ins.selectedMemberId).get();
        if (doc.exists) existingMember = doc;
      }

      const memberData = {
        fullName: `${ins.prenom || ''} ${ins.nom || ''}`.trim(),
        phone: ins.telephone || null, plan,
        birthday: ins.dateNaissance || null,
        expiresOn: ins.periodTo || new Date(Date.now() + 365 * 86400000).toISOString().split('T')[0],
        photo: ins.profilePicture || null, email: ins.email || null,
        cin: ins.cin || null, location: gymId,
        contractNumber: ins.contractNumber || null, commercial: ins.commercial || null,
        pdfUrl: ins.pdfUrl || null, balance: ins.totals?.balance || 0,
        balanceDeadline: req.body.balanceDeadline || null,
        payments: ins.payments || null, inscriptionId: req.params.id,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      let memberId, memberRef;
      if (existingMember) {
        memberId = existingMember.id; memberRef = existingMember.ref;
        if (memberData.photo?.startsWith('data:image')) memberData.photo = await uploadBase64ToStorage(memberData.photo, `members/${memberId}/profile.jpg`);
        await memberRef.update(memberData);
      } else {
        const qrToken = crypto.randomBytes(16).toString('hex');
        memberRef = await db.collection('members').add({ ...memberData, qrToken, createdAt: admin.firestore.FieldValue.serverTimestamp(), confirmedBy: req.user?.preferred_username || 'Admin' });
        memberId = memberRef.id;
        if (memberData.photo?.startsWith('data:image')) {
          const url = await uploadBase64ToStorage(memberData.photo, `members/${memberId}/profile.jpg`);
          await memberRef.update({ photo: url });
        }
      }

      // Link existing payments
      const orphanPayments = await db.collection('payments').where('inscriptionId', '==', req.params.id).get();
      for (const p of orphanPayments.docs) await p.ref.update({ memberId });

      // Auto-record registration payment if not already there
      if (!orphanPayments.docs.some(p => p.data().type === 'registration')) {
        const espece   = Number(ins.payments?.espece   || 0);
        const carte    = Number(ins.payments?.carte    || ins.payments?.tpe || 0);
        const virement = Number(ins.payments?.virement || 0);
        const cheque   = Number(ins.payments?.cheque   || 0);
        const totalPaid = espece + carte + virement + cheque;
        if (totalPaid > 0) {
          const method = carte > 0 ? 'Carte Bancaire' : espece > 0 ? 'Espèces' : virement > 0 ? 'Virement' : 'Chèque';
          const chequePhoto = ins.chequePhoto?.startsWith('data:image')
            ? await uploadBase64ToStorage(ins.chequePhoto, `members/${memberId}/cheques/${Date.now()}.jpg`)
            : ins.chequePhoto || null;
          await db.collection('payments').add({
            memberId, inscriptionId: req.params.id, gymId,
            amount: totalPaid, plan, date: new Date().toISOString(), method,
            paymentsSplit: { espece, carte, virement, cheque },
            chequePhoto, note: 'Paiement inscription initiale',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            recordedBy: req.user?.preferred_username || 'Admin', type: 'registration',
          });
        }
      }

      await insRef.update({ status: 'awaiting_payment', memberId: memberRef.id, memberCreatedAt: admin.firestore.FieldValue.serverTimestamp(), memberCreatedBy: req.user?.preferred_username || 'Admin' });
      
      // ✅ MEGAEYE FAST SYNC: Flag as accepted in local SQLite
      lc.updatePendingStatus(req.params.id, 'accepted');

      invalidateCache(apiCache.inscriptions);
      const memberSnap = await memberRef.get();
      res.json({ ok: true, member: { id: memberRef.id, ...memberSnap.data() }, nextStep: 'Go to Payments page to confirm and record the payment' });
    } catch (err) {
      console.error('Confirm Inscription Error:', err);
      res.status(500).json({ error: 'Failed to confirm inscription' });
    }
  });

  // ── DELETE /api/inscriptions/:id ──────────────────────────────────────────
  router.delete('/api/inscriptions/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('pending_members').doc(req.params.id).delete();
      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete inscription' }); }
  });

  return router;
};
