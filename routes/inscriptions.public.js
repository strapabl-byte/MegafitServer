'use strict';
// routes/inscriptions.public.js
// Public tablet-facing routes — form submission & member search require NO auth
// Financial routes (settle-balance, debtors) require Azure token auth

const { Router } = require('express');
const { verifyAzureToken } = require('../middleware/auth');

module.exports = function inscriptionsPublicRouter({ db, admin, lc, apiCache, uploadBase64ToStorage, invalidateCache }) {
  const router = Router();

  const GYM_ALIAS_MAP = {
    'dokarat': 'dokarat', 'dokkarat': 'dokarat', 'doukkarate': 'dokarat', 'fes dokkarat': 'dokarat', 'doukarat': 'dokarat',
    'marjane': 'marjane', 'saiss': 'marjane', 'fes saiss': 'marjane', 'marjan': 'marjane',
    'casa1':   'casa1',   'anfa': 'casa1', 'casa anfa': 'casa1', 'casablanca anfa': 'casa1',
    'casa2':   'casa2',   'lady': 'casa2', 'casa lady': 'casa2', 'casa lady anfa': 'casa2', 'lady anfa': 'casa2',
  };
  const VALID_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];

  // ── GET /public/next-contract-number ──────────────────────────────────────
  // Read-only peek — does NOT increment the counter. Safe to call any time.
  router.get('/public/next-contract-number', async (req, res) => {
    try {
      const doc = await db.collection('settings').doc('contractCounter').get();
      const num = doc.exists && doc.data().current ? doc.data().current + 1 : 15001;
      res.json({ contractNumber: num.toString().padStart(6, '0') });
    } catch {
      res.json({ contractNumber: '015001', fallback: true });
    }
  });

  // ── GET /public/debtors ─────────────────────────────────────── 🔒 AUTH ──
  router.get('/public/debtors', verifyAzureToken, async (req, res) => {
    try {
      const gymId = (req.query.gymId || '').toLowerCase().trim();
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });

      const refresh = req.query.refresh === 'true';
      const cached = lc.getDebtors(gymId);
      if (cached.length > 0 && !refresh) {
        console.log(`[Debtors/Public] ⚡ SQLite hit: ${cached.length} debtors for ${gymId}`);
        return res.json(cached.map(m => ({
          id: m.id,
          fullName: m.full_name,
          phone: m.phone,
          balance: m.balance,
          gymId: m.gym_id,
          plan: m.plan,
          subscriptionName: m.subscription_name,
          photo: m.photo,
          balanceDeadline: m.balance_deadline || null,
          contractNumber: m.contract_number || null,
          createdAt: m.created_at || null,
        })));
      }

      console.log(`[Debtors/Public] ${refresh ? 'FORCED REFRESH' : 'SQLite empty'} for ${gymId} → Firebase fallback`);
      const snap = await db.collection('members')
        .where('location', '==', gymId)
        .where('balance', '>', 0)
        .orderBy('balance', 'desc')
        .limit(1000)
        .get();

      const result = snap.docs.map(d => {
        const m = d.data();
        return {
          id: d.id,
          fullName: m.fullName || '',
          phone: m.phone || '',
          balance: Number(m.balance) || 0,
          gymId: m.location || gymId,
          plan: m.plan || '',
          subscriptionName: m.subscriptionName || '',
          photo: m.photo || null,
          balanceDeadline: m.balanceDeadline || null,
          contractNumber: m.contractNumber || null,
          createdAt: m.createdAt?._seconds ? new Date(m.createdAt._seconds * 1000).toISOString() : null,
        };
      });

      // ── 🧹 Prune ghost debtors from SQLite on forced refresh ─────────────
      // Removes test members that were deleted in Firebase but are still
      // cached locally with balance > 0, causing them to ghost in the list.
      if (refresh && cached.length > 0) {
        const freshIds = new Set(result.map(m => m.id));
        const ghosts = cached.filter(m => !freshIds.has(m.id));
        if (ghosts.length > 0) {
          console.log(`[Debtors/Public] 🧹 Pruning ${ghosts.length} ghost(s) from SQLite [${gymId}]: ${ghosts.map(g => g.full_name).join(', ')}`);
          for (const ghost of ghosts) lc.pruneStaleMember(ghost.id);
        }
      }

      if (result.length > 0) {
        const byGym = {};
        result.forEach(m => {
          const g = m.gymId || gymId;
          if (!byGym[g]) byGym[g] = [];
          byGym[g].push(m);
        });
        for (const [gid, members] of Object.entries(byGym)) {
          lc.upsertMembers(gid, members.map(m => ({ ...m, location: gid })));
        }
        console.log(`[Debtors/Public] 💾 Cached ${result.length} debtors from Firebase → SQLite`);
      }

      res.json(result);
    } catch (err) {
      console.error('[Debtors/Public] Error:', err);
      res.status(500).json({ error: 'Failed to fetch debtors' });
    }
  });

  // ── POST /public/settle-balance ─────────────────────────────── 🔒 AUTH ──
  // Requires Azure token — this endpoint modifies member financial records.
  router.post('/public/settle-balance', verifyAzureToken, async (req, res) => {
    try {
      const { memberId, gymId: rawGymId, amount, method, paymentsSplit, note,
              chequePhoto, chequePhotoBack, signatureClient, signatureCommercial, commercialName } = req.body;

      const gymId = (rawGymId || '').toLowerCase().trim();
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });
      if (!memberId || !amount) return res.status(400).json({ error: 'Missing memberId or amount' });

      const memberRef = db.collection('members').doc(memberId);
      const memberSnap = await memberRef.get();
      if (!memberSnap.exists) return res.status(404).json({ error: 'Member not found' });

      const member = memberSnap.data();
      const memberGymId = member.location || member.gymId || '';
      if (memberGymId !== gymId) return res.status(403).json({ error: 'Gym mismatch — access denied' });

      let cin = member.cin || '';
      if (!cin && member.inscriptionId) {
        try {
          const insDoc = await db.collection('pending_members').doc(member.inscriptionId).get();
          if (insDoc.exists && insDoc.data().cin) {
            cin = insDoc.data().cin;
          }
        } catch (insErr) {
          console.warn('[Settle/Public] Inscription fetch fallback failed:', insErr.message);
        }
      }

      const oldBalance = Number(member.balance || 0);
      const payAmount = Number(amount);
      if (payAmount <= 0 || payAmount > oldBalance) return res.status(400).json({ error: 'Invalid payment amount' });
      const newBalance = Math.max(0, oldBalance - payAmount);

      let chequeUrl = null, chequeUrlBack = null, sigClientUrl = null, sigCommUrl = null;
      if (chequePhoto) chequeUrl = await uploadBase64ToStorage(chequePhoto, `payments/${memberId}/${Date.now()}_cheque_recto.jpg`);
      if (chequePhotoBack) chequeUrlBack = await uploadBase64ToStorage(chequePhotoBack, `payments/${memberId}/${Date.now()}_cheque_verso.jpg`);
      if (signatureClient) sigClientUrl = await uploadBase64ToStorage(signatureClient, `payments/${memberId}/${Date.now()}_sig_client.png`);
      if (signatureCommercial) sigCommUrl = await uploadBase64ToStorage(signatureCommercial, `payments/${memberId}/${Date.now()}_sig_comm.png`);

      const today = new Date().toISOString().slice(0, 10);

      const payRef = await db.collection('payments').add({
        memberId, gymId,
        amount: payAmount,
        method: method || 'Espèces',
        paymentsSplit: paymentsSplit || null,
        date: new Date().toISOString(),
        type: 'balance_settlement',
        note: note || `Règlement reste à payer (Ancien: ${oldBalance} DH, Payé: ${payAmount} DH)`,
        chequePhoto: chequeUrl, chequePhotoBack: chequeUrlBack,
        signatureClient: sigClientUrl, signatureCommercial: sigCommUrl,
        commercialName: (commercialName || 'COMMERCIAL').toUpperCase(),
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        source: 'inscription_form',
      });

      const updatePayload = {
        balance: newBalance,
        lastPaymentDate: today,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      if (cin && !member.cin) {
        updatePayload.cin = cin;
      }
      if (newBalance === 0) updatePayload.balanceDeadline = admin.firestore.FieldValue.delete();
      await memberRef.update(updatePayload);

      const updatedSnap = await memberRef.get();
      lc.upsertMembers(gymId, [{ id: memberId, ...updatedSnap.data() }]);

      try {
        const docId = `${gymId}_${today}`;
        const normMethod = (method || '').toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim();
        const addedDoc = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
          nom: member.fullName || '', tel: member.phone || '', contrat: member.contractNumber || '',
          commercial: (commercialName || 'COMMERCIAL').toUpperCase(), cin: cin || '',
          prix: payAmount,
          espece:   Number(paymentsSplit?.espece   || 0) || (['especes','espece','cash'].includes(normMethod) ? payAmount : 0),
          tpe:      Number(paymentsSplit?.carte     || paymentsSplit?.tpe     || 0) || (['tpe','carte','carte bancaire'].includes(normMethod) ? payAmount : 0),
          virement: Number(paymentsSplit?.virement  || 0) || (normMethod === 'virement' ? payAmount : 0),
          cheque:   Number(paymentsSplit?.cheque    || 0) || (normMethod === 'cheque' ? payAmount : 0),
          abonnement: member.subscriptionName || member.plan || '',
          reste: newBalance,
          note_reste: newBalance > 0 ? `Reste: ${newBalance} DH` : '',
          source: 'reste_settlement',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        await db.collection('megafit_daily_register').doc(docId).set(
          { gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
          { merge: true }
        );
        const newSnap = await addedDoc.get();
        lc.upsertRegister(gymId, today, [{ id: addedDoc.id, ...newSnap.data() }]);
      } catch (regErr) {
        console.warn('[Settle/Public] Register update failed (non-blocking):', regErr.message);
      }

      console.log(`✅ [Settle/Public] ${member.fullName} | Paid: ${payAmount} DH | New balance: ${newBalance} DH`);
      res.json({ ok: true, paymentId: payRef.id, newBalance });

    } catch (err) {
      console.error('[Settle/Public] Error:', err);
      res.status(500).json({ error: 'Failed to settle balance' });
    }
  });

  // ── POST /public/inscriptions ─────────────────────────────────────────────
  router.post('/public/inscriptions', async (req, res) => {
    try {
      const data = req.body;
      const rawGymId = (data.gymId || req.query.gymId || req.query.gym || '').toLowerCase().trim();

      const normalizedGymId = GYM_ALIAS_MAP[rawGymId] || null;
      if (!normalizedGymId) {
        console.error(`❌ [INSCRIPTION REJECTED] Unknown gymId: "${rawGymId}"`);
        return res.status(400).json({
          error: 'Identifiant de salle invalide. Veuillez vous reconnecter et réessayer.',
          received: rawGymId,
          allowed: ['dokarat', 'marjane', 'casa1', 'casa2'],
        });
      }

      // 🛑 Strip large base64 blobs FIRST — needed before dedup AND before Firestore write
      // ⚠️ MUST be here (outer scope) so profilePicture is accessible AFTER the transaction
      const { profilePicture, memberSignature, chequePhoto, chequePhotoVerso, ...safeData } = data;

      // 🛡️ DEDUPLICATION CHECK
      const recentSnap = await db.collection('pending_members')
        .where('gymId', '==', normalizedGymId)
        .where('nom', '==', (data.nom || '').trim())
        .where('prenom', '==', (data.prenom || '').trim())
        .get();

      if (!recentSnap.empty) {
        const docs = recentSnap.docs.map(d => ({ id: d.id, ...d.data() }));
        docs.sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
        const latest = docs[0];
        const lastCreated = latest.createdAt?.toDate ? latest.createdAt.toDate() : new Date(0);
        if (Date.now() - lastCreated.getTime() < 2 * 60 * 1000) {
          console.warn(`[DEDUP] /public/inscriptions: Found duplicate for ${data.prenom} ${data.nom}`);
          // ✅ Still sync photo to SQLite on dedup — it was never stored on the first (failed) attempt
          try {
            lc.setPending({
              id: latest.id,
              gymId: normalizedGymId,
              nom: data.nom, prenom: data.prenom,
              subscriptionName: data.subscriptionName,
              contractNumber: latest.contractNumber,
              periodFrom: data.periodFrom || null, periodTo: data.periodTo || null,
              totals: data.totals, payments: data.payments,
              cin: data.cin || null, adresse: data.adresse || null, ville: data.ville || null,
              email: data.email || null, commercial: data.commercial || null,
              telephone: data.telephone || null, dateNaissance: data.dateNaissance || null,
              profilePicture: profilePicture || data.photoUrl || null,
              chequePhoto: chequePhoto || null,
              chequePhotoVerso: chequePhotoVerso || null,
              createdAt: { _seconds: Math.floor(Date.now() / 1000) }
            });
          } catch (_) {}
          return res.json({ id: latest.id, contractNumber: latest.contractNumber, ok: true, alreadySubmitted: true });
        }
      }

      const result = await db.runTransaction(async (t) => {
        const counterRef = db.collection('settings').doc('contractCounter');
        const cSnap = await t.get(counterRef);
        let nextNum = 15000;
        if (!cSnap.exists) { t.set(counterRef, { current: nextNum }); }
        else { nextNum = cSnap.data().current + 1; t.update(counterRef, { current: nextNum }); }

        const finalNum = nextNum.toString().padStart(6, '0');
        const newDocRef = db.collection('pending_members').doc();

        // safeData already stripped at top of handler (profilePicture, memberSignature etc. removed)
        t.set(newDocRef, {
          ...safeData,
          contractNumber: finalNum,
          gymId: normalizedGymId,
          source: 'web',
          status: 'pending',
          hasPhoto: !!(profilePicture || data.photoUrl),
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return { id: newDocRef.id, contractNumber: finalNum };
      });

      const id = result.id;
      const finalContractNumber = result.contractNumber;

      // 📦 SQLite gets the base64 photo — no size limit
      // NOTE: setPending() reads data.profilePicture (camelCase) — must use that key!
      lc.setPending({
        id,
        gymId: normalizedGymId,
        nom: data.nom,
        prenom: data.prenom,
        subscriptionName: data.subscriptionName,
        contractNumber: finalContractNumber,
        periodFrom: data.periodFrom || null,
        periodTo: data.periodTo || null,
        totals: data.totals,
        payments: data.payments,
        cin: data.cin || null,
        adresse: data.adresse || null,
        ville: data.ville || null,
        email: data.email || null,
        commercial: data.commercial || null,
        telephone: data.telephone || null,
        dateNaissance: data.dateNaissance || null,
        profilePicture: profilePicture || data.photoUrl || null,  // ✅ camelCase — setPending reads data.profilePicture
        chequePhoto: chequePhoto || null,
        chequePhotoVerso: chequePhotoVerso || null,
        createdAt: { _seconds: Math.floor(Date.now() / 1000) }
      });

      invalidateCache(apiCache.inscriptions);
      console.log(`[Inscription] ✅ Success for ${data.prenom} ${data.nom}`);
      res.json({ id, ok: true, contractNumber: finalContractNumber });
    } catch (err) {
      console.error('❌ [PUBLIC INSCRIPTION ERROR]:', err);
      res.status(500).json({
        error: 'Failed to submit inscription',
        detail: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
      });
    }
  });

  // ── GET /public/members/search ────────────────────────────────────────────
  router.get('/public/members/search', async (req, res) => {
    try {
      const q = (req.query.q || '').trim().toLowerCase();
      if (q.length < 2) return res.json([]);

      const searchTerm = `%${q}%`;
      const rows = lc.db.prepare(`
        SELECT id, full_name, phone, cin, birthday, gym_id, photo, expires_on, bonus_3months,
               email, adresse, ville
        FROM members_cache
        WHERE (LOWER(full_name) LIKE ? OR LOWER(cin) LIKE ? OR phone LIKE ?)
          AND (status IS NULL OR status = ''
               OR (LOWER(status) NOT LIKE '%delet%'
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
        expiresOn: m.expires_on || null,
        bonus3Months: m.bonus_3months === 1,
        email:   m.email   || '',
        adresse: m.adresse || '',
        ville:   m.ville   || '',
      })));
    } catch (err) {
      console.error('Public Member Search Error:', err);
      res.status(500).json({ error: 'Failed to search members' });
    }
  });

  // ── GET /public/members/:id/detail ───────────────────────────────────────
  router.get('/public/members/:id/detail', async (req, res) => {
    try {
      const memberId = req.params.id;
      if (!memberId) return res.status(400).json({ error: 'id required' });

      const snap = await db.collection('members').doc(memberId).get();
      if (!snap.exists) {
        lc.pruneStaleMember(memberId);
        return res.status(410).json({ error: 'Member deleted', deleted: true });
      }

      const d = snap.data();
      if (d.deleted === true || d.isDeleted === true || d.status === 'deleted') {
        lc.pruneStaleMember(memberId);
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
        expiresOn: d.expiresOn || null,
        bonus3Months: d.bonus3Months || false,
      });
    } catch (err) {
      console.error('Member detail error:', err);
      res.status(500).json({ error: 'Failed to fetch member detail' });
    }
  });

  return router;
};
