'use strict';
// routes/inscriptions.js — public form submissions + admin dashboard management

const { Router } = require('express');
const crypto = require('crypto');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function inscriptionsRouter({ db, admin, lc, apiCache, uploadBase64ToStorage, invalidateCache }) {
  const router = Router();

  function planToAbonnement(plan, subscriptionName) {
    if (subscriptionName) return subscriptionName.toUpperCase();
    const map = { Monthly: '1 MOIS', Quarterly: '3 MOIS', 'Semi-Annual': '6 MOIS', Annual: '1 AN' };
    return map[plan] || plan || '1 AN';
  }

  async function autoRegisterCA({ gymId = 'dokarat', date, nom, tel, cin, plan, subscriptionName, amount, method, commercial, contrat, payments: split, reste, note }) {
    try {
      const today = date || new Date().toISOString().slice(0, 10);
      const docId = `${gymId}_${today}`;
      const totalAmt = Number(amount) || 0;
      let tpe = 0, espece = 0, virement = 0, cheque = 0;

      if (split && typeof split === 'object') {
        tpe      = Number(split.carte    || split.tpe      || 0);
        espece   = Number(split.espece   || 0);
        virement = Number(split.virement || 0);
        cheque   = Number(split.cheque   || 0);
      } else {
        const methodMap = {
          'Espèces': 'espece', Cash: 'espece', espece: 'espece',
          TPE: 'tpe', 'Carte Bancaire': 'tpe', tpe: 'tpe', carte: 'tpe',
          Virement: 'virement', virement: 'virement',
          'Chèque': 'cheque', Cheque: 'cheque', cheque: 'cheque',
        };
        const field = methodMap[method] || 'espece';
        if (field === 'tpe')           tpe      = totalAmt;
        else if (field === 'virement') virement = totalAmt;
        else if (field === 'cheque')   cheque   = totalAmt;
        else                           espece   = totalAmt;
      }

      const prix = tpe + espece + virement + cheque || totalAmt;
      const addedDoc = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
        nom: nom || '', tel: tel || '', contrat: contrat || '',
        commercial: (commercial || 'FORM').toUpperCase(), cin: cin || '',
        prix, tpe, espece, virement, cheque,
        abonnement: planToAbonnement(plan, subscriptionName),
        reste:      Number(reste) || 0,
        note_reste: note || (reste > 0 ? `Reste: ${reste} DH` : ''),
        source: 'inscription_auto',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: 'auto',
      });
      await db.collection('megafit_daily_register').doc(docId).set(
        { gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true }
      );
      
      const newSnap = await addedDoc.get();
      if (lc && typeof lc.upsertRegister === 'function') {
        lc.upsertRegister(gymId, today, [{ id: addedDoc.id, ...newSnap.data() }]);
      }
      
      console.log(`✅ AutoRegisterCA (Inscription): ${nom} | ${prix} DH → ${docId}`);
    } catch (err) {
      console.error('⚠️  AutoRegisterCA (non-blocking):', err.message);
    }
  }

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
  // ✅ SQLite-first: reads from local cache — zero Firestore cost during typing
  // Deleted/inactive members are excluded from results.
  router.get('/public/members/search', async (req, res) => {
    try {
      const q = (req.query.q || '').trim().toLowerCase();
      if (q.length < 2) return res.json([]);

      const searchTerm = `%${q}%`;
      const rows = lc.db.prepare(`
        SELECT id, full_name, phone, cin, birthday, gym_id, photo
        FROM members_cache
        WHERE (LOWER(full_name) LIKE ? OR LOWER(cin) LIKE ? OR phone LIKE ?)
          AND (status IS NULL OR status = ''
               OR (LOWER(status) NOT LIKE '%delet%'
               AND LOWER(status) NOT LIKE '%inactiv%'
               AND LOWER(status) NOT LIKE '%supprim%'))
        LIMIT 5
      `).all(searchTerm, searchTerm, searchTerm);

      res.json(rows.map(m => ({
        id: m.id,
        fullName: m.full_name,
        nom:    (m.full_name || '').split(' ').slice(1).join(' ') || '',
        prenom: (m.full_name || '').split(' ')[0] || '',
        cin:     m.cin     || '',
        phone:   m.phone   || '',
        birthday: m.birthday || '',
        gymId:   m.gym_id  || '',
        photo:   m.photo   || '',
      })));
    } catch (err) {
      console.error('Public Member Search Error:', err);
      res.status(500).json({ error: 'Failed to search members' });
    }
  });

  // ── GET /public/members/:id/detail ───────────────────────────────────────
  // Called ONCE when user selects a member from search results.
  // Does a single Firestore read to get email, adresse, ville not stored in SQLite.
  // Returns 410 Gone if the member has been deleted.
  router.get('/public/members/:id/detail', async (req, res) => {
    try {
      const memberId = req.params.id;
      if (!memberId) return res.status(400).json({ error: 'id required' });

      const snap = await db.collection('members').doc(memberId).get();

      // Member document deleted from Firestore entirely
      if (!snap.exists) {
        lc.pruneStaleMember(memberId); // remove from SQLite so it won't appear again
        return res.status(410).json({ error: 'Member deleted', deleted: true });
      }

      const d = snap.data();

      // Member soft-deleted (deleted/isDeleted flag)
      if (d.deleted === true || d.isDeleted === true || d.status === 'deleted') {
        lc.pruneStaleMember(memberId); // clean from SQLite cache
        return res.status(410).json({ error: 'Member deleted', deleted: true });
      }

      res.json({
        id:       snap.id,
        fullName: d.fullName || d.full_name || '',
        nom:      d.nom      || '',
        prenom:   d.prenom   || '',
        cin:      d.cin      || '',
        phone:    d.phone    || d.telephone || '',
        email:    d.email    || '',
        birthday: d.birthday || d.dateNaissance || '',
        adresse:  d.adresse  || '',
        ville:    d.ville    || '',
        gymId:    d.gymId    || '',
        photo:    d.photo    || '',
      });
    } catch (err) {
      console.error('Member detail error:', err);
      res.status(500).json({ error: 'Failed to fetch member detail' });
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

      // ── Robust plan derivation — handles "24 MOIS", "2 ANS", "12 MOIS", etc. ──
      const sName = (ins.subscriptionName || '').toLowerCase();
      const monthMatch  = sName.match(/(\d+)\s*mois/);
      const yearMatch   = sName.match(/(\d+)\s*an/);
      const totalMonths = monthMatch ? parseInt(monthMatch[1]) : (yearMatch ? parseInt(yearMatch[1]) * 12 : 1);
      let plan = 'Monthly';
      if      (totalMonths >= 12) plan = 'Annual';
      else if (totalMonths >= 6 ) plan = 'Semi-Annual';
      else if (totalMonths >= 3 ) plan = 'Quarterly';
      else                        plan = 'Monthly';

      // ── Expiry: trust the form's pre-calculated dates (most accurate) ───────
      // Fall back to a month-based calculation only if periodTo is missing.
      let expiresOn = ins.periodTo || null;
      if (!expiresOn) {
        const start = ins.periodFrom ? new Date(ins.periodFrom) : new Date();
        if (ins.durationYears)         start.setFullYear(start.getFullYear() + Number(ins.durationYears));
        else if (ins.durationMonths)   start.setMonth(start.getMonth() + Number(ins.durationMonths));
        else if (ins.durationDays)     start.setDate(start.getDate() + Number(ins.durationDays));
        else                           start.setFullYear(start.getFullYear() + 1); // absolute last resort
        expiresOn = start.toISOString().split('T')[0];
      }

      // Only link if explicitly selected via autocomplete in the form
      let existingMember = null;
      if (ins.selectedMemberId) {
        const doc = await db.collection('members').doc(ins.selectedMemberId).get();
        if (doc.exists) existingMember = doc;
      }

      const memberData = {
        fullName: `${ins.prenom || ''} ${ins.nom || ''}`.trim(),
        phone: ins.telephone || null, plan,
        // ✅ FIX: Save the real subscription label (e.g. "24 MOIS LOCAL") on the member
        subscriptionName: ins.subscriptionName || null,
        birthday: ins.dateNaissance || null,
        // ✅ FIX: Use form-calculated periodTo directly
        expiresOn,
        periodFrom: ins.periodFrom || null,
        periodTo:   expiresOn,
        photo: ins.profilePicture || null, email: ins.email || null,
        // ✅ CIN always propagated
        cin: ins.cin || null,
        adresse: ins.adresse || null, ville: ins.ville || null,
        location: gymId,
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
              chequePhoto, note: 'Paiement inscription initiale — À confirmer sur la page Paiements',
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
              recordedBy: req.user?.preferred_username || 'Admin', type: 'registration',
            });
          // ✅ NOTE: autoRegisterCA is intentionally NOT called here.
          // The register entry is created ONLY when the admin explicitly
          // confirms the payment on the Payments page (complete-inscription endpoint).
          // Calling it here caused duplicate entries in the daily register.
        }
      }

      await insRef.update({ status: 'awaiting_payment', memberId: memberRef.id, memberCreatedAt: admin.firestore.FieldValue.serverTimestamp(), memberCreatedBy: req.user?.preferred_username || 'Admin' });
      
      // ✅ MEGAEYE FAST SYNC: Flag as accepted in local SQLite
      lc.updatePendingStatus(req.params.id, 'accepted');

      invalidateCache(apiCache.inscriptions);
      const memberSnap = await memberRef.get();

      // ✅ INSTANT MEMBER CACHE: Push new/updated member into SQLite immediately
      // Without this, the member is invisible in the Members page until the next hourly sync.
      try {
        lc.upsertMembers(gymId, [{ id: memberRef.id, ...memberSnap.data() }]);
        console.log(`💾 SQLite member cache updated for: ${memberData.fullName}`);
      } catch(cacheErr) {
        console.warn('⚠️  SQLite member cache update failed (non-blocking):', cacheErr.message);
      }

      res.json({ ok: true, member: { id: memberRef.id, ...memberSnap.data() }, nextStep: 'Go to Payments page to confirm and record the payment' });
    } catch (err) {
      console.error('Confirm Inscription Error:', err);
      res.status(500).json({ error: 'Failed to confirm inscription' });
    }
  });

  // ── POST /api/inscriptions/recover-register ──────────────────────────────
  // Finds all accepted (awaiting_payment) inscriptions from the last N days
  // that are missing from the daily register and injects them.
  // Safe to run multiple times — uses source+contrat guard to avoid duplicates.
  router.post('/recover-register', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, daysBack = 7 } = req.body;
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - Number(daysBack));

      // 1. Get all accepted-but-unconfirmed inscriptions
      let query = db.collection('pending_members')
        .where('status', '==', 'awaiting_payment');
      if (gymId) query = query.where('gymId', '==', gymId);
      const snap = await query.get();

      const recovered = [];
      const skipped   = [];
      const errors    = [];

      for (const doc of snap.docs) {
        const ins = doc.data();
        const insGymId = ins.gymId || 'dokarat';
        const fullName = `${ins.prenom || ''} ${ins.nom || ''}`.trim();
        const contrat  = ins.contractNumber || '';

        // Determine date to use for register (prefer createdAt, fallback to today)
        let dateStr = new Date().toISOString().slice(0, 10);
        if (ins.createdAt?._seconds) {
          dateStr = new Date(ins.createdAt._seconds * 1000).toISOString().slice(0, 10);
        } else if (ins.memberCreatedAt?._seconds) {
          dateStr = new Date(ins.memberCreatedAt._seconds * 1000).toISOString().slice(0, 10);
        }

        // Skip if too old
        if (new Date(dateStr) < cutoff) {
          skipped.push({ id: doc.id, name: fullName, reason: 'Too old' });
          continue;
        }

        // Check Firestore register for existing entry with this contrat number
        if (contrat) {
          const regDocId = `${insGymId}_${dateStr}`;
          const existSnap = await db.collection('megafit_daily_register')
            .doc(regDocId).collection('entries')
            .where('contrat', '==', contrat)
            .limit(1).get();
          if (!existSnap.empty) {
            skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'Already in register' });
            continue;
          }
        }

        // Also check SQLite
        if (contrat) {
          const existInSQLite = lc.db.prepare(
            `SELECT id FROM register_cache WHERE gym_id=? AND contrat=? AND date=? LIMIT 1`
          ).get(insGymId, contrat, dateStr);
          if (existInSQLite) {
            skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'Already in SQLite register' });
            continue;
          }
        }

        // Build payment split from inscription data
        const espece   = Number(ins.payments?.espece   || 0);
        const carte    = Number(ins.payments?.carte    || ins.payments?.tpe || 0);
        const virement = Number(ins.payments?.virement || 0);
        const cheque   = Number(ins.payments?.cheque   || 0);
        const totalPaid = espece + carte + virement + cheque || Number(ins.totals?.paid || ins.totals?.grandTotal || 0);

        if (totalPaid <= 0) {
          skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'No payment amount found' });
          continue;
        }

        const method = carte > 0 ? 'Carte Bancaire' : espece > 0 ? 'Espèces' : virement > 0 ? 'Virement' : 'Chèque';

        try {
          await autoRegisterCA({
            gymId: insGymId,
            date: dateStr,
            nom: fullName,
            tel: ins.telephone || '',
            cin: ins.cin || '',
            plan: ins.plan || 'Annual',
            subscriptionName: ins.subscriptionName || '',
            amount: totalPaid,
            method,
            commercial: ins.commercial || 'FORM',
            contrat,
            payments: { espece, carte, virement, cheque },
            reste: Math.max(0, (ins.totals?.grandTotal || 0) - totalPaid),
            note: `[RÉCUPÉRÉ] Inscription N°${contrat} — acceptée le ${dateStr}`,
          });
          recovered.push({ id: doc.id, name: fullName, date: dateStr, amount: totalPaid, gymId: insGymId });
          console.log(`🔧 RECOVER: ${fullName} | ${totalPaid} DH | ${insGymId}_${dateStr}`);
        } catch (e) {
          errors.push({ id: doc.id, name: fullName, error: e.message });
        }
      }

      res.json({
        ok: true,
        summary: `${recovered.length} recovered, ${skipped.length} skipped, ${errors.length} errors`,
        recovered,
        skipped,
        errors,
      });
    } catch (err) {
      console.error('Recover Register Error:', err);
      res.status(500).json({ error: 'Recovery failed', detail: err.message });
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
