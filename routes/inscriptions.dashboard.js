'use strict';
// routes/inscriptions.dashboard.js
// Dashboard-facing inscription routes — ALL require Azure AD token
// Handles: waiting list CRUD, PDF save, inscription confirmation

const { Router } = require('express');
const crypto = require('crypto');
const { verifyAzureToken } = require('../middleware/auth');

module.exports = function inscriptionsDashboardRouter({ db, admin, lc, apiCache, invalidateCache }) {
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

      const entriesRef = db.collection('megafit_daily_register').doc(docId).collection('entries');
      if (contrat) {
        const dupContract = await entriesRef.where('contrat', '==', contrat).limit(1).get();
        if (!dupContract.empty) {
          console.warn(`[DEDUP] autoRegisterCA: Duplicate contract ${contrat} found for ${gymId}/${today}. Skipping.`);
          return;
        }
      } else if (nom && totalAmt > 0) {
        const fiveMinsAgo = new Date(Date.now() - 5 * 60 * 1000);
        const dupName = await entriesRef
          .where('nom', '==', nom)
          .where('prix', '==', totalAmt)
          .where('createdAt', '>=', fiveMinsAgo)
          .limit(1).get();
        if (!dupName.empty) {
          console.warn(`[DEDUP] autoRegisterCA: Identical entry for ${nom} (${totalAmt} DH) found in last 5m. Skipping.`);
          return;
        }
      }

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

  // ── GET /api/inscriptions ─────────────────────────────────────────────────
  router.get('/api/inscriptions', verifyAzureToken, async (req, res) => {
    try {
      const isFullAdmin = req.assignedGyms?.includes('all');

      let gymIdsToFetch;
      if (isFullAdmin) {
        gymIdsToFetch = req.query.gymId ? [req.query.gymId] : null;
      } else {
        gymIdsToFetch = req.assignedGyms || [];
        if (gymIdsToFetch.length === 0) return res.json([]);
      }

      const cacheKey = gymIdsToFetch ? gymIdsToFetch.join(',') : 'all';
      const cached = apiCache.inscriptions[cacheKey];
      if (cached && Date.now() - cached.ts < 30000) return res.json(cached.data);

      let allDocs = [];

      if (gymIdsToFetch === null) {
        const snap = await db.collection('pending_members')
          .where('source', '==', 'web')
          .where('status', 'in', ['pending', 'awaiting_payment'])
          .get();
        allDocs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      } else if (gymIdsToFetch.length === 1) {
        const snap = await db.collection('pending_members')
          .where('source', '==', 'web')
          .where('status', 'in', ['pending', 'awaiting_payment'])
          .where('gymId', '==', gymIdsToFetch[0])
          .get();
        allDocs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      } else {
        const snaps = await Promise.all(
          gymIdsToFetch.map(gid =>
            db.collection('pending_members')
              .where('source', '==', 'web')
              .where('status', 'in', ['pending', 'awaiting_payment'])
              .where('gymId', '==', gid)
              .get()
          )
        );
        snaps.forEach(snap => snap.docs.forEach(d => allDocs.push({ id: d.id, ...d.data() })));
      }

      const data = allDocs.sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));

      // 🖼️ Enrich with profilePicture + pdfUrl from SQLite
      const enriched = data.map(ins => {
        const sqliteEntry = lc.getPendingById(ins.id);
        return {
          ...ins,
          profilePicture: ins.profilePicture || sqliteEntry?.profile_picture || null,
          pdfUrl: ins.pdfUrl || sqliteEntry?.pdf_url || null,
        };
      });

      apiCache.inscriptions[cacheKey] = { data: enriched, ts: Date.now() };
      res.json(enriched);
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

      const insRef = db.collection('pending_members').doc(req.params.id);
      await insRef.update({ pdfUrl, pdfUploadedAt: admin.firestore.FieldValue.serverTimestamp() });

      // ✅ Write-through to SQLite pending_cache
      try {
        lc.db.prepare(`UPDATE pending_cache SET pdf_url=? WHERE id=?`).run(pdfUrl, req.params.id);
      } catch (_) {}

      // ✅ Propagate pdfUrl → member doc + members_cache (if already confirmed)
      try {
        const insDoc = await insRef.get();
        const insData = insDoc.data();
        if (insData?.memberId) {
          await db.collection('members').doc(insData.memberId).update({ pdfUrl });
          lc.db.prepare(`UPDATE members_cache SET pdf_url=? WHERE id=?`).run(pdfUrl, insData.memberId);
          console.log(`[set-pdf] ✅ pdfUrl propagated to member ${insData.memberId}`);
        }
      } catch (propErr) {
        console.warn('[set-pdf] pdfUrl propagation to member failed (non-blocking):', propErr.message);
      }

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
      const insId = req.params.id;
      const result = await db.runTransaction(async (t) => {
        const insRef = db.collection('pending_members').doc(insId);
        const insDoc = await t.get(insRef);

        if (!insDoc.exists) throw new Error('Inscription introuvable');
        const ins = insDoc.data();

        if (ins.status === 'converted') throw new Error('Cette inscription est déjà confirmée.');
        if (ins.memberId) throw new Error('Un membre est déjà associé à cette inscription.');

        const gymId = ins.gymId || 'dokarat';

        // Resolve plan
        const sName = (ins.subscriptionName || '').toLowerCase();
        const monthMatch  = sName.match(/(\d+)\s*mois/);
        const yearMatch   = sName.match(/(\d+)\s*an/);
        const totalMonths = monthMatch ? parseInt(monthMatch[1]) : (yearMatch ? parseInt(yearMatch[1]) * 12 : 1);
        let plan = 'Monthly';
        if (totalMonths >= 12) plan = 'Annual';
        else if (totalMonths >= 6) plan = 'Semi-Annual';
        else if (totalMonths >= 3) plan = 'Quarterly';

        const memberData = {
          fullName: `${ins.prenom || ''} ${ins.nom || ''}`.trim(),
          phone: ins.telephone || null,
          plan,
          subscriptionName: ins.subscriptionName || null,
          expiresOn: ins.periodTo || null,
          periodFrom: ins.periodFrom || null,
          location: gymId,
          contractNumber: ins.contractNumber || null,
          inscriptionId: insId,
          balance: ins.totals?.balance || 0,
          pdfUrl: ins.pdfUrl || null,
          source: 'inscription_form',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          confirmedBy: req.user?.preferred_username || 'Admin'
        };

        // 🛡️ DEDUPLICATION CHECK (inside transaction)
        const dupQuery = await db.collection('members')
          .where('location', '==', gymId)
          .where('fullName', '==', memberData.fullName)
          .limit(1).get();

        if (!dupQuery.empty) {
          const existing = dupQuery.docs[0];
          t.update(insRef, { status: 'awaiting_payment', memberId: existing.id });
          return { member: { id: existing.id, ...existing.data() }, alreadyExisted: true };
        }

        const newMemberRef = db.collection('members').doc();
        const qrToken = crypto.randomBytes(16).toString('hex');

        // 🖼️ Photo: prefer Storage URL, fall back to base64 from tablet
        const memberPhoto = ins.photoUrl ||
          (ins.profilePicture && ins.profilePicture.length < 200000 ? ins.profilePicture : null) || null;

        t.set(newMemberRef, { ...memberData, qrToken, status: 'Active', photo: memberPhoto });
        t.update(insRef, { status: 'awaiting_payment', memberId: newMemberRef.id });

        return { member: { id: newMemberRef.id, ...memberData, qrToken, status: 'Active', photo: memberPhoto } };
      });

      const member = result.member;
      const gymId = member.location || 'dokarat';

      // ✅ Instant SQLite member cache update
      try {
        lc.upsertMembers(gymId, [member]);
        console.log(`💾 SQLite member cache updated for: ${member.fullName}`);
      } catch (cacheErr) {
        console.warn('⚠️ SQLite member cache update failed (non-blocking):', cacheErr.message);
      }

      // ✅ Auto-register: if paid at inscription, write to daily register immediately
      if (!result.alreadyExisted) {
        try {
          const ins = await db.collection('pending_members').doc(insId).get().then(d => d.data());
          const espece   = Number(ins?.payments?.espece   || 0);
          const carte    = Number(ins?.payments?.carte    || ins?.payments?.tpe || 0);
          const virement = Number(ins?.payments?.virement || 0);
          const cheque   = Number(ins?.payments?.cheque   || 0);
          const totalPaid = espece + carte + virement + cheque || Number(ins?.totals?.paid || 0);

          if (totalPaid > 0) {
            const dateStr = new Date().toISOString().slice(0, 10);
            const method = carte > 0 ? 'Carte Bancaire' : espece > 0 ? 'Espèces' : virement > 0 ? 'Virement' : 'Chèque';
            await autoRegisterCA({
              gymId, date: dateStr,
              nom: member.fullName,
              tel: ins?.telephone || '',
              cin: ins?.cin || '',
              plan: member.plan || 'Monthly',
              subscriptionName: ins?.subscriptionName || '',
              amount: totalPaid, method,
              commercial: ins?.commercial || ins?.submittedBy || 'FORM',
              contrat: ins?.contractNumber || '',
              payments: { espece, carte, virement, cheque },
              reste: Math.max(0, Number(ins?.totals?.total || 0) - totalPaid),
              note: `Inscription N°${ins?.contractNumber || ''} — ${ins?.subscriptionName || ''}`,
            });
            console.log(`💸 Register entry auto-created for ${member.fullName} — ${totalPaid} DH`);
          }
        } catch (regErr) {
          console.warn('⚠️ Auto-register on confirm failed (non-blocking):', regErr.message);
        }
      }

      res.json({ ok: true, member, nextStep: 'Payment recorded and register updated automatically' });
    } catch (err) {
      console.error('Confirm Inscription Error:', err);
      res.status(500).json({ error: 'Failed to confirm inscription' });
    }
  });

  // ── DELETE /api/inscriptions/:id ─────────────────────────────────────────
  const { requireAdmin } = require('../middleware/auth');
  router.delete('/api/inscriptions/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('pending_members').doc(req.params.id).delete();
      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete inscription' }); }
  });

  return router;
};
