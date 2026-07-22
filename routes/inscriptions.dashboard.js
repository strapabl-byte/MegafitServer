'use strict';
// routes/inscriptions.dashboard.js
// Dashboard-facing inscription routes — ALL require Azure AD token
// Handles: waiting list CRUD, PDF save, inscription confirmation

const { Router } = require('express');
const crypto = require('crypto');
const { verifyAzureToken } = require('../middleware/auth');

module.exports = function inscriptionsDashboardRouter({ db, admin, lc, apiCache, uploadBase64ToStorage, invalidateCache }) {
  const router = Router();

  function planToAbonnement(plan, subscriptionName) {
    if (subscriptionName) return subscriptionName.toUpperCase();
    const map = { Monthly: '1 MOIS', Quarterly: '3 MOIS', 'Semi-Annual': '6 MOIS', Annual: '1 AN' };
    return map[plan] || plan || '1 AN';
  }

  async function autoRegisterCA({ gymId = 'dokarat', date, nom, tel, cin, plan, subscriptionName, amount, method, commercial, contrat, payments: split, reste, note, chequePhoto, chequePhotoBack }) {
    try {
      const today = date || new Date().toISOString().slice(0, 10);
      const docId = `${gymId}_${today}`;
      const totalAmt = Number(amount) || 0;

      const entriesRef = db.collection('megafit_daily_register').doc(docId).collection('entries');
      if (contrat) {
        const dupContract = await entriesRef.where('contrat', '==', contrat).limit(1).get();
        if (!dupContract.empty) {
          // ✅ CIN BACKFILL: If existing entry is missing a CIN but we now have one, update it
          const existingEntry = dupContract.docs[0];
          const existingCin = existingEntry.data().cin || '';
          if (cin && cin.trim() !== '' && existingCin.trim() === '') {
            await existingEntry.ref.update({ cin: cin.trim() });
            if (lc && typeof lc.db !== 'undefined') {
              try { lc.db.prepare('UPDATE register_cache SET cin = ? WHERE id = ?').run(cin.trim(), existingEntry.id); } catch (_) {}
            }
            console.log(`[CIN BACKFILL] Updated CIN for contract ${contrat}: ${cin}`);
          }
          console.warn(`[DEDUP] autoRegisterCA: Duplicate contract ${contrat} found for ${gymId}/${today}. Skipping insert.`);
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
        chequePhoto: chequePhoto || null,
        chequePhotoBack: chequePhotoBack || null,
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
          .where('status', 'in', ['pending', 'awaiting_payment', 'locked'])
          .get();
        allDocs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      } else if (gymIdsToFetch.length === 1) {
        const snap = await db.collection('pending_members')
          .where('source', '==', 'web')
          .where('status', 'in', ['pending', 'awaiting_payment', 'locked'])
          .where('gymId', '==', gymIdsToFetch[0])
          .get();
        allDocs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      } else {
        const snaps = await Promise.all(
          gymIdsToFetch.map(gid =>
            db.collection('pending_members')
              .where('source', '==', 'web')
              .where('status', 'in', ['pending', 'awaiting_payment', 'locked'])
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
          chequePhoto: ins.chequePhoto || sqliteEntry?.cheque_photo || null,
          chequePhotoVerso: ins.chequePhotoVerso || sqliteEntry?.cheque_photo_back || null,
          pdfUrl: ins.pdfUrl || sqliteEntry?.pdf_url || null,
          // ✅ Restore member signature from SQLite (stripped from Firestore due to 1MB limit)
          memberSignature: ins.memberSignature || sqliteEntry?.member_signature || null,
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
      const insId = req.params.id;
      const body = { ...req.body };

      // 🖼️ If a new profile picture was sent as base64, upload it to Storage
      // and replace the field with the real URL before saving to Firestore
      if (body.profilePicture && body.profilePicture.startsWith('data:')) {
        try {
          const photoUrl = await uploadBase64ToStorage(
            body.profilePicture,
            `members/${insId}/profile_${Date.now()}.jpg`
          );
          body.profilePicture = photoUrl;  // swap base64 → Storage URL
          body.photoUrl = photoUrl;         // also set photoUrl for confirm-time use
          console.log(`[PATCH /inscriptions] ✅ Profile photo uploaded to Storage: ${photoUrl}`);

          // Write-through to SQLite so confirm picks it up
          try {
            lc.db.prepare(`UPDATE pending_cache SET profile_picture = ? WHERE id = ?`).run(photoUrl, insId);
          } catch (_) {}
        } catch (photoErr) {
          console.warn('[PATCH /inscriptions] ⚠️ Photo upload failed (non-blocking):', photoErr.message);
          delete body.profilePicture; // don't save base64 blob to Firestore
        }
      }

      const updateData = { ...body, updatedAt: admin.firestore.FieldValue.serverTimestamp() };
      await db.collection('pending_members').doc(insId).update(updateData);

      if (body.memberId) {
        const orphans = await db.collection('payments').where('inscriptionId', '==', insId).get();
        if (!orphans.empty) {
          const batch = db.batch();
          orphans.forEach(p => batch.update(p.ref, { memberId: body.memberId }));
          await batch.commit();
        }
      }

      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true, photoUrl: body.photoUrl || null });
    } catch (err) {
      console.error('PATCH /inscriptions error:', err);
      res.status(500).json({ error: 'Failed to update inscription' });
    }
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
      let insData = null;

      // 🖼️ Resolve the profile photo to a Storage URL BEFORE the transaction —
      // uploads can't run inside a Firestore transaction, and a base64 blob can
      // exceed the inline limit and get dropped (member ends up photo-less while
      // the inscription PDF still has it).
      let resolvedPhoto = null;
      try {
        const preDoc = await db.collection('pending_members').doc(insId).get();
        const preIns = preDoc.exists ? preDoc.data() : {};
        const preSql = lc.getPendingById ? lc.getPendingById(insId) : null;
        const raw = preIns.photoUrl || preIns.profilePicture || preSql?.profile_picture || null;
        if (raw && typeof raw === 'string') {
          if (raw.startsWith('data:')) {
            try {
              resolvedPhoto = await uploadBase64ToStorage(raw, `members/${insId}/profile_${Date.now()}.jpg`);
              try { lc.db.prepare('UPDATE pending_cache SET profile_picture = ? WHERE id = ?').run(resolvedPhoto, insId); } catch (_) {}
            } catch (e) { console.warn('[confirm] photo upload failed, keeping base64:', e.message); resolvedPhoto = raw; }
          } else {
            resolvedPhoto = raw; // already a Storage URL
          }
        }
      } catch (e) { console.warn('[confirm] photo pre-resolve failed:', e.message); }

      const result = await db.runTransaction(async (t) => {
        const insRef = db.collection('pending_members').doc(insId);
        const insDoc = await t.get(insRef);

        if (!insDoc.exists) throw new Error('Inscription introuvable');
        const ins = insDoc.data();
        insData = ins;

        if (ins.status === 'converted') throw new Error('Cette inscription est déjà confirmée.');
        if (ins.status === 'locked') throw new Error('Cette inscription est suspendue par la direction. Débloquez-la avant de confirmer.');

        const gymId = ins.gymId || 'dokarat';
        const sqliteEntry = lc.getPendingById(insId);

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
          phone: ins.telephone || sqliteEntry?.telephone || null,
          plan,
          subscriptionName: ins.subscriptionName || sqliteEntry?.subscriptionName || null,
          birthday: ins.dateNaissance || sqliteEntry?.date_naissance || null,
          email: ins.email || sqliteEntry?.email || null,
          cin: ins.cin || sqliteEntry?.cin || null,
          adresse: ins.adresse || sqliteEntry?.adresse || null,
          ville: ins.ville || sqliteEntry?.ville || null,
          expiresOn: ins.periodTo || sqliteEntry?.period_to || null,
          periodFrom: ins.periodFrom || sqliteEntry?.period_from || null,
          location: gymId,
          contractNumber: ins.contractNumber || sqliteEntry?.contract_number || null,
          inscriptionId: insId,
          balance: ins.totals?.balance || sqliteEntry?.balance || 0,
          pdfUrl: ins.pdfUrl || sqliteEntry?.pdf_url || null,
          commercial: ins.commercial || sqliteEntry?.commercial || null,
          source: 'inscription_form',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          confirmedBy: req.user?.preferred_username || 'Admin'
        };

        // Check if there is an existing member already linked to this inscription
        let existingMember = null;
        if (ins.memberId) {
          try {
            const mRef = db.collection('members').doc(ins.memberId);
            const mDoc = await t.get(mRef);
            if (mDoc.exists) {
              existingMember = mDoc;
            }
          } catch (e) {
            console.warn('[confirm] existing member lookup failed:', e.message);
          }
        }

        // 🛡️ DEDUPLICATION CHECK (inside transaction)
        let dupQuery = null;
        if (!existingMember) {
          dupQuery = await db.collection('members')
            .where('location', '==', gymId)
            .where('fullName', '==', memberData.fullName)
            .limit(1).get();
        }

        if (existingMember || (dupQuery && !dupQuery.empty)) {
          const existing = existingMember || dupQuery.docs[0];
          const existingData = existing.data();
          
          let newBalance;
          if (existingData.inscriptionId === insId) {
            newBalance = Number(memberData.balance || 0);
          } else {
            newBalance = Number(existingData.balance || 0) + Number(memberData.balance || 0);
          }

          t.update(existing.ref, {
            plan: memberData.plan,
            subscriptionName: memberData.subscriptionName || existingData.subscriptionName,
            expiresOn: memberData.expiresOn || existingData.expiresOn,
            periodFrom: memberData.periodFrom || existingData.periodFrom,
            balance: newBalance,
            contractNumber: memberData.contractNumber || existingData.contractNumber,
            inscriptionId: insId,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
          });

          t.update(insRef, { status: 'awaiting_payment', memberId: existing.id });
          return { member: { id: existing.id, ...existingData, plan: memberData.plan, expiresOn: memberData.expiresOn, balance: newBalance, inscriptionId: insId }, alreadyExisted: true };
        }

        const newMemberRef = db.collection('members').doc();
        const qrToken = crypto.randomBytes(16).toString('hex');

        // 🖼️ Photo: prefer the pre-resolved Storage URL (uploaded above), then any
        // existing URL, then a small inline base64 as a last resort.
        const memberPhoto = resolvedPhoto ||
          ins.photoUrl ||
          sqliteEntry?.profile_picture ||
          (ins.profilePicture && ins.profilePicture.length < 200000 ? ins.profilePicture : null) ||
          null;

        t.set(newMemberRef, { ...memberData, qrToken, status: 'Active', photo: memberPhoto });
        t.update(insRef, { status: 'awaiting_payment', memberId: newMemberRef.id });

        return { member: { id: newMemberRef.id, ...memberData, qrToken, status: 'Active', photo: memberPhoto } };
      });

      const member = result.member;
      const gymId = member.location || 'dokarat';

      // Fix FieldValue for SQLite caching
      if (member.createdAt && typeof member.createdAt === 'object' && !member.createdAt.toDate) {
        member.createdAt = new Date().toISOString();
      }

      // ✅ Instant SQLite member cache update
      try {
        lc.upsertMembers(gymId, [member]);
        console.log(`💾 SQLite member cache updated for: ${member.fullName}`);
      } catch (cacheErr) {
        console.warn('⚠️ SQLite member cache update failed (non-blocking):', cacheErr.message);
      }

      // 🧾 Billing-receipt email status (reliable, server-side). If the member has NO
      // email, the receipt can't be auto-sent → flag it red in Paiements + raise a red
      // notification. If they DO have an email, mark 'pending' — the dashboard then
      // generates the receipt PDF and sends it, updating the status to sent/error.
      try {
        const hasEmail = !!(member.email && /\S+@\S+\.\S+/.test(String(member.email)));
        const receiptStatus = hasEmail ? 'pending' : 'no_email';
        member.receiptEmailStatus = receiptStatus;
        await db.collection('members').doc(member.id).update({
          receiptEmailStatus: receiptStatus,
          receiptEmailTo: hasEmail ? member.email : null,
          receiptEmailAt: null,
        }).catch(() => {});
        try { lc.setMemberReceiptStatus?.(member.id, { status: receiptStatus, to: hasEmail ? member.email : null, at: null }); } catch (_) {}
        if (!hasEmail) {
          lc.addNotification({
            type: 'receipt_email_missing',
            gymId: member.location || insData?.gymId || '',
            title: `🧾 Reçu non envoyé — ${member.fullName}`,
            message: `Email manquant — le reçu de paiement n'a pas pu être envoyé. Ajoutez un email dans Paiements puis renvoyez-le.`,
            severity: 'critical',
            route: '/payments',
            icon: '🧾',
            refId: `receipt_missing_${member.id}`,
          });
        }
      } catch (rcErr) { console.warn('⚠️ Receipt status init failed (non-blocking):', rcErr.message); }

      // ✅ Auto-register: if paid at inscription, write to daily register immediately
        try {
          const espece   = Number(insData?.payments?.espece   || 0);
          const carte    = Number(insData?.payments?.carte    || insData?.payments?.tpe || 0);
          const virement = Number(insData?.payments?.virement || 0);
          const cheque   = Number(insData?.payments?.cheque   || 0);
          const totalPaid = espece + carte + virement + cheque || Number(insData?.totals?.paid || 0);

          if (totalPaid > 0) {
            // Retrieve cheque photos from SQLite if they were stripped from Firestore
            const sqliteEntry = lc.getPendingById(insId);
            const rawChequeRecto = insData?.chequePhoto || sqliteEntry?.cheque_photo;
            const rawChequeVerso = insData?.chequePhotoVerso || sqliteEntry?.cheque_photo_back;

            let chequeUrl = null, chequeUrlBack = null;
            if (rawChequeRecto) chequeUrl = await uploadBase64ToStorage(rawChequeRecto, `payments/${member.id}/${Date.now()}_cheque_recto.jpg`);
            if (rawChequeVerso) chequeUrlBack = await uploadBase64ToStorage(rawChequeVerso, `payments/${member.id}/${Date.now()}_cheque_verso.jpg`);

            // 1. Create a real payment record in Firestore
            await db.collection('payments').add({
              memberId: member.id,
              inscriptionId: insId,
              gymId,
              amount: totalPaid,
              plan: member.plan || 'Monthly',
              method: carte > 0 ? 'Carte Bancaire' : espece > 0 ? 'Espèces' : virement > 0 ? 'Virement' : 'Chèque',
              paymentsSplit: { espece, carte, virement, cheque },
              chequePhoto: chequeUrl,
              chequePhotoBack: chequeUrlBack,
              recordedBy: req.user?.preferred_username || 'Admin',
              type: 'registration',
              date: new Date().toISOString(),
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
            });

            const dateStr = new Date().toISOString().slice(0, 10);
            const method = carte > 0 ? 'Carte Bancaire' : espece > 0 ? 'Espèces' : virement > 0 ? 'Virement' : 'Chèque';
            await autoRegisterCA({
              gymId, date: dateStr,
              nom: member.fullName,
              tel: insData?.telephone || '',
              cin: insData?.cin || '',
              plan: member.plan || 'Monthly',
              subscriptionName: insData?.subscriptionName || '',
              amount: totalPaid, method,
              commercial: insData?.commercial || insData?.submittedBy || 'FORM',
              contrat: insData?.contractNumber || '',
              payments: { espece, carte, virement, cheque },
              reste: Number(insData?.totals?.balance ?? Math.max(0, Number(insData?.totals?.total || 0) - totalPaid)),
              note: `Inscription N°${insData?.contractNumber || ''} — ${insData?.subscriptionName || ''}`,
              chequePhoto: chequeUrl,
              chequePhotoBack: chequeUrlBack,
            });
            console.log(`💸 Payment record & Register entry auto-created for ${member.fullName} — ${totalPaid} DH`);
          }
        } catch (regErr) {
          console.warn('⚠️ Auto-register on confirm failed (non-blocking):', regErr.message);
        }

      // ✅ Invalidate inscription cache — next refreshPendingInscriptions() gets fresh data
      // Without this, the 30s cache returns stale status:'pending' and the card never disappears
      invalidateCache(apiCache.inscriptions);
      if (lc && typeof lc.updatePendingStatus === 'function') {
        lc.updatePendingStatus(insId, 'awaiting_payment');
      }

      // 🔔 Notification: inscription confirmed
      try {
        lc.addNotification({
          type: 'inscription_confirmed',
          gymId: insData?.gymId || '',
          title: `✅ Inscription confirmée — ${member.fullName}`,
          message: `Contrat #${insData?.contractNumber || 'N/A'} · ${insData?.subscriptionName || ''} · Membre activé`,
          severity: 'info',
          route: '/members',
          icon: '✅',
          refId: `confirmed_${insId}`,
        });
      } catch(_) {}

      res.json({ ok: true, member, confirmedId: insId, nextStep: 'Payment recorded and register updated automatically' });
    } catch (err) {
      // 🔎 Some Firestore/gRPC errors carry an EMPTY .message, which used to collapse
      // into a useless generic 500 with no clue what actually failed. Dig out whatever
      // the error actually carries so the cause is visible in the UI and the logs.
      const detail =
        (err && err.message) ||
        (err && err.details) ||
        (err && err.code != null && `Firestore/gRPC code ${err.code}`) ||
        (typeof err === 'string' ? err : '') ||
        (err ? Object.prototype.toString.call(err) : 'unknown error');

      console.error('Confirm Inscription Error:', {
        insId:   req.params.id,
        name:    err?.name,
        code:    err?.code,
        details: err?.details,
        message: err?.message,
        stack:   err?.stack,
      });

      res.status(500).json({
        error: detail || 'Failed to confirm inscription',
        code:  err?.code ?? null,
        name:  err?.name ?? null,
      });
    }
  });

  // ── POST /api/inscriptions/:id/lock ──────────────────────────────────────
  const { requireAdmin } = require('../middleware/auth');
  router.post('/api/inscriptions/:id/lock', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const insRef = db.collection('pending_members').doc(req.params.id);
      const insDoc = await insRef.get();
      if (!insDoc.exists) return res.status(404).json({ error: 'Inscription introuvable' });

      const current = insDoc.data();
      const newStatus = current.status === 'locked' ? 'pending' : 'locked';
      await insRef.update({
        status: newStatus,
        lockedBy: newStatus === 'locked' ? (req.user?.preferred_username || 'Admin') : null,
        lockedAt: newStatus === 'locked' ? admin.firestore.FieldValue.serverTimestamp() : null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      invalidateCache(apiCache.inscriptions);
      console.log(`[Lock] Inscription ${req.params.id} → ${newStatus} by ${req.user?.preferred_username || 'Admin'}`);
      res.json({ ok: true, status: newStatus });
    } catch (err) {
      console.error('Lock inscription error:', err);
      res.status(500).json({ error: 'Failed to lock/unlock inscription' });
    }
  });

  // ── DELETE /api/inscriptions/:id ─────────────────────────────────────────
  router.delete('/api/inscriptions/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('pending_members').doc(req.params.id).delete();
      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete inscription' }); }
  });


  // ── POST /api/manager-tokens ────────────────────────────────────────────
  // Sync manager token from dashboard (Door Firestore) to main Firestore
  // so the server can validate manager QR codes on the inscription tablet.
  router.post('/api/manager-tokens', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { id, managerName, gymId, isActive, expiresAt, role, createdBy } = req.body;
      if (!id || !managerName || !gymId) {
        return res.status(400).json({ error: 'id, managerName, gymId required' });
      }
      await db.collection('managerTokens').doc(id).set({
        managerName,
        gymId,
        isActive: isActive !== false,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        role: role || 'manager',
        createdBy: createdBy || req.user?.preferred_username || 'admin',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      console.log(`[ManagerToken] ✅ Synced: ${managerName} → ${gymId} (${id})`);
      res.json({ ok: true, id });
    } catch (err) {
      console.error('[ManagerToken] Error:', err);
      res.status(500).json({ error: 'Failed to sync manager token' });
    }
  });

  // ── POST /api/inscriptions/reassess ─────────────────────────────────────
  // Re-run the smarter (rules-based) assessment over EXISTING pending
  // inscriptions, so previously mis-flagged ones are corrected without waiting
  // for a new submission. Admin only. Body: { gymId? } (defaults to the caller's
  // gyms / all for admin).
  const { assessInscription } = require('../services/inscription-assessment');
  const { DEFAULT_SUBSCRIPTION_GROUPS } = require('./config');
  router.post('/api/inscriptions/reassess', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const gymId = req.body?.gymId || null;
      let q = db.collection('pending_members').where('status', '==', 'pending');
      if (gymId) q = q.where('gymId', '==', gymId);
      const snap = await q.limit(300).get();

      // Cache each gym's catalog once.
      const catalogCache = {};
      const catalogFor = async (gid) => {
        const key = gid || 'dokarat';
        if (catalogCache[key]) return catalogCache[key];
        let groups = DEFAULT_SUBSCRIPTION_GROUPS;
        try {
          const cfg = await db.collection('config').doc(`inscription-${key}`).get();
          const g = cfg.exists && cfg.data().subscriptionGroups;
          if (Array.isArray(g) && g.length) groups = g;
        } catch (_) {}
        catalogCache[key] = groups;
        return groups;
      };

      let updated = 0; const summary = { ok: 0, warning: 0, error: 0 };
      for (const doc of snap.docs) {
        const m = doc.data();
        const t = m.totals || {};
        const groups = await catalogFor(m.gymId);
        const a = assessInscription({
          subscriptionName: m.subscriptionName || '',
          subPrice: Number(t.subscription || 0),
          totalDue: Number(t.total || 0),
          totalPaid: Number(t.paid || 0),
          balance: Number(t.balance || 0),
          phone: m.telephone || '',
          email: m.email || '',
          cin: m.cin || '',
          nom: m.nom || '',
          prenom: m.prenom || '',
          dateNaissance: m.dateNaissance || '',
          periodFrom: m.periodFrom || '',
          periodTo: m.periodTo || '',
        }, groups);
        await doc.ref.update({ aiAssessment: { ...a, checkedAt: new Date().toISOString(), model: 'rules-v2-reassess' } });
        updated++; summary[a.status] = (summary[a.status] || 0) + 1;
      }
      invalidateCache(apiCache.inscriptions);
      console.log(`[AI] 🔄 Re-assessed ${updated} pending inscriptions:`, summary);
      res.json({ ok: true, updated, summary });
    } catch (err) {
      console.error('[AI] reassess error:', err);
      res.status(500).json({ error: 'Failed to reassess inscriptions' });
    }
  });

  return router;
};
