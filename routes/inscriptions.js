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

      // 🛡️ DEDUPLICATION CHECK: Prevent identical entries in the daily register
      const entriesRef = db.collection('megafit_daily_register').doc(docId).collection('entries');
      if (contrat) {
        const dupContract = await entriesRef.where('contrat', '==', contrat).limit(1).get();
        if (!dupContract.empty) {
          console.warn(`[DEDUP] autoRegisterCA: Duplicate contract ${contrat} found for ${gymId}/${today}. Skipping.`);
          return;
        }
      } else if (nom && totalAmt > 0) {
        // Fallback check by name and amount if within last 5 minutes
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

  // ── GET /public/debtors ───────────────────────────────────────────────────
  // 🌐 No auth required — secured by strict gymId validation only.
  // Architecture: SQLite (Render) → Firebase (hard fallback) → cache back to SQLite
  router.get('/public/debtors', async (req, res) => {
    try {
      const gymId = (req.query.gymId || '').toLowerCase().trim();
      const VALID_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });

      // 1. ⚡ SQLite first — fast, zero Firebase cost (unless refresh requested)
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

      // 2. 🔥 Firebase hard fallback — when SQLite is empty or refresh is requested
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

      // 3. 💾 Cache Firebase results back into SQLite for future fast reads.
      // IMPORTANT: Use each member's own gymId (m.gymId), NOT the query gymId.
      // Using the query gymId would store casa1 members as dokarat, causing cross-gym leakage!
      if (result.length > 0) {
        // Group members by their actual gym to cache them correctly
        const byGym = {};
        result.forEach(m => {
          const g = m.gymId || gymId;
          if (!byGym[g]) byGym[g] = [];
          byGym[g].push(m);
        });
        for (const [gid, members] of Object.entries(byGym)) {
          lc.upsertMembers(gid, members.map(m => ({ ...m, location: gid })));
        }
        console.log(`[Debtors/Public] 💾 Cached ${result.length} debtors from Firebase → SQLite (by their own gymId)`);
      }

      res.json(result);
    } catch (err) {
      console.error('[Debtors/Public] Error:', err);
      res.status(500).json({ error: 'Failed to fetch debtors' });
    }
  });

  // ── POST /public/settle-balance ───────────────────────────────────────────
  // 🌐 Allows inscription form tablets to settle member balances.
  // Write-through: Firebase first (source of truth), then SQLite sync.
  router.post('/public/settle-balance', async (req, res) => {
    try {
      const { memberId, gymId: rawGymId, amount, method, paymentsSplit, note,
              chequePhoto, chequePhotoBack, signatureClient, signatureCommercial, commercialName } = req.body;

      const gymId = (rawGymId || '').toLowerCase().trim();
      const VALID_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });
      if (!memberId || !amount) return res.status(400).json({ error: 'Missing memberId or amount' });

      const memberRef = db.collection('members').doc(memberId);
      const memberSnap = await memberRef.get();
      if (!memberSnap.exists) return res.status(404).json({ error: 'Member not found' });

      const member = memberSnap.data();
      const memberGymId = member.location || member.gymId || '';
      if (memberGymId !== gymId) return res.status(403).json({ error: 'Gym mismatch — access denied' });

      const oldBalance = Number(member.balance || 0);
      const payAmount = Number(amount);
      if (payAmount <= 0 || payAmount > oldBalance) return res.status(400).json({ error: 'Invalid payment amount' });
      const newBalance = Math.max(0, oldBalance - payAmount);

      // Upload images to Storage
      let chequeUrl = null, chequeUrlBack = null, sigClientUrl = null, sigCommUrl = null;
      if (chequePhoto) chequeUrl = await uploadBase64ToStorage(chequePhoto, `payments/${memberId}/${Date.now()}_cheque_recto.jpg`);
      if (chequePhotoBack) chequeUrlBack = await uploadBase64ToStorage(chequePhotoBack, `payments/${memberId}/${Date.now()}_cheque_verso.jpg`);
      if (signatureClient) sigClientUrl = await uploadBase64ToStorage(signatureClient, `payments/${memberId}/${Date.now()}_sig_client.png`);
      if (signatureCommercial) sigCommUrl = await uploadBase64ToStorage(signatureCommercial, `payments/${memberId}/${Date.now()}_sig_comm.png`);

      const today = new Date().toISOString().slice(0, 10);

      // 1. 🔥 Firebase: Create payment record
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

      // 2. 🔥 Firebase: Update member balance (write-through)
      const updatePayload = {
        balance: newBalance,
        lastPaymentDate: today,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      if (newBalance === 0) updatePayload.balanceDeadline = admin.firestore.FieldValue.delete();
      await memberRef.update(updatePayload);

      // 3. 💾 SQLite: Immediately sync the updated member (keeps cache fresh)
      const updatedSnap = await memberRef.get();
      lc.upsertMembers(gymId, [{ id: memberId, ...updatedSnap.data() }]);

      // 4. 📒 Daily Register entry
      try {
        const docId = `${gymId}_${today}`;
        const addedDoc = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
          nom: member.fullName || '', tel: member.phone || '', contrat: member.contractNumber || '',
          commercial: (commercialName || 'COMMERCIAL').toUpperCase(), cin: member.cin || '',
          prix: payAmount, espece: 0, tpe: 0, virement: 0, cheque: 0,
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

      // 🏦 STRICT GYM VALIDATION — reject unknown gyms at the gate, never let bad data in.
      // All 4 canonical variants + common aliases accepted.
      const GYM_ALIAS_MAP = {
        'dokarat':    'dokarat', 'dokkarat': 'dokarat', 'doukkarate': 'dokarat', 'fes dokkarat': 'dokarat', 'doukarat': 'dokarat',
        'marjane':    'marjane', 'saiss': 'marjane', 'fes saiss': 'marjane', 'marjan': 'marjane',
        'casa1':      'casa1',   'anfa': 'casa1', 'casa anfa': 'casa1', 'casablanca anfa': 'casa1',
        'casa2':      'casa2',   'lady': 'casa2', 'casa lady': 'casa2', 'casa lady anfa': 'casa2', 'lady anfa': 'casa2',
      };
      const normalizedGymId = GYM_ALIAS_MAP[rawGymId] || null;

      if (!normalizedGymId) {
        console.error(`❌ [INSCRIPTION REJECTED] Unknown gymId: "${rawGymId}" from body.gymId="${data.gymId}"`);
        return res.status(400).json({
          error: 'Identifiant de salle invalide. Veuillez vous reconnecter et réessayer.',
          received: rawGymId,
          allowed: ['dokarat', 'marjane', 'casa1', 'casa2'],
        });
      }

      // 🛡️ DEDUPLICATION CHECK (Index-free approach)
      // We fetch entries with same name/gym (Equality filters only = no index needed)
      const recentSnap = await db.collection('pending_members')
        .where('gymId', '==', normalizedGymId)
        .where('nom', '==', (data.nom || '').trim())
        .where('prenom', '==', (data.prenom || '').trim())
        .get();
      
      if (!recentSnap.empty) {
        // Sort and check date in memory to avoid "Missing Index" errors
        const docs = recentSnap.docs.map(d => ({ id: d.id, ...d.data() }));
        docs.sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
        
        const latest = docs[0];
        const lastCreated = latest.createdAt?.toDate ? latest.createdAt.toDate() : new Date(0);
        const diffMs = Date.now() - lastCreated.getTime();
        
        if (diffMs < 2 * 60 * 1000) {
          console.warn(`[DEDUP] /public/inscriptions: Found duplicate for ${data.prenom} ${data.nom}`);
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
        
        t.set(newDocRef, { 
          ...data, 
          contractNumber: finalNum, 
          gymId: normalizedGymId, 
          source: 'web', 
          status: 'pending', 
          createdAt: admin.firestore.FieldValue.serverTimestamp() 
        });
        
        return { id: newDocRef.id, contractNumber: finalNum };
      });

      console.log(`[Inscription] Syncing to SQLite for ${id}...`);
      lc.setPending({
        id, 
        gymId: normalizedGymId, 
        nom: data.nom, 
        prenom: data.prenom,
        subscriptionName: data.subscriptionName,
        totals: data.totals,
        payments: data.payments,
        cin: data.cin || null,
        adresse: data.adresse || null,
        ville: data.ville || null,
        email: data.email || null,
        commercial: data.commercial || null,
        contract_number: finalContractNumber,
        period_from: data.periodFrom || null,
        period_to: data.periodTo || null,
        telephone: data.telephone || null,
        date_naissance: data.dateNaissance || null,
        profile_picture: data.photoUrl || null,
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
  // ✅ SQLite-first: reads from local cache — zero Firestore cost during typing
  // Deleted/inactive members are excluded from results.
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
        expiresOn: d.expiresOn || null,
        bonus3Months: d.bonus3Months || false,
      });
    } catch (err) {
      console.error('Member detail error:', err);
      res.status(500).json({ error: 'Failed to fetch member detail' });
    }
  });



  // ── GET /api/inscriptions ─────────────────────────────────────────────
  router.get('/api/inscriptions', verifyAzureToken, async (req, res) => {
    try {
      const isFullAdmin = req.assignedGyms?.includes('all');

      // 🔒 SERVER-SIDE GYM ENFORCEMENT
      // Admins : respect ?gymId param (or return all if missing)
      // Managers: ALWAYS restrict to their assignedGyms, ignore client param
      let gymIdsToFetch;
      if (isFullAdmin) {
        gymIdsToFetch = req.query.gymId ? [req.query.gymId] : null; // null = all
      } else {
        gymIdsToFetch = req.assignedGyms || [];
        if (gymIdsToFetch.length === 0) return res.json([]);
      }

      const cacheKey = gymIdsToFetch ? gymIdsToFetch.join(',') : 'all';
      const cached = apiCache.inscriptions[cacheKey];
      if (cached && Date.now() - cached.ts < 30000) return res.json(cached.data);

      let allDocs = [];

      if (gymIdsToFetch === null) {
        // Admin, no filter
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
        // Multiple gyms — parallel queries
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
      apiCache.inscriptions[cacheKey] = { data, ts: Date.now() };
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
      const insId = req.params.id;
      const result = await db.runTransaction(async (t) => {
        const insRef = db.collection('pending_members').doc(insId);
        const insDoc = await t.get(insRef);

        if (!insDoc.exists) throw new Error('Inscription introuvable');
        const ins = insDoc.data();

        if (ins.status === 'converted') throw new Error('Cette inscription est déjà confirmée.');
        if (ins.memberId) throw new Error('Un membre est déjà associé à cette inscription.');

        const gymId = ins.gymId || 'dokarat';
        
        // ── Resolve plan ──
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
          inscriptionId: insId, // ✅ CRITICAL: link member to original inscription
          balance: ins.totals?.balance || 0, // ✅ CRITICAL: transfer balance
          source: 'inscription_form',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          confirmedBy: req.user?.preferred_username || 'Admin'
        };

        // 🛡️ DEDUPLICATION CHECK (INSIDE TRANSACTION)
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

        t.set(newMemberRef, {
          ...memberData,
          qrToken,
          status: 'Active',
          photo: ins.photoUrl || null
        });

        t.update(insRef, {
          status: 'awaiting_payment',
          memberId: newMemberRef.id
        });

        return { member: { id: newMemberRef.id, ...memberData, qrToken, status: 'Active' } };
      });

      const member = result.member;
      const gymId = member.location || 'dokarat';

      // ✅ INSTANT MEMBER CACHE: Push new/updated member into SQLite immediately
      try {
        lc.upsertMembers(gymId, [member]);
        console.log(`💾 SQLite member cache updated for: ${member.fullName}`);
      } catch (cacheErr) {
        console.warn('⚠️ SQLite member cache update failed (non-blocking):', cacheErr.message);
      }

      res.json({
        ok: true,
        member,
        nextStep: 'Go to Payments page to confirm and record the payment'
      });
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

  // ── POST /api/inscriptions/recover-members ───────────────────────────────
  // Finds inscriptions that have a PDF (form was fully submitted) but whose
  // member is missing from the members collection or the SQLite cache.
  // Safe to run multiple times — dedup logic prevents duplicate members.
  // 🔒 Super Admin only.
  router.post('/recover-members', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId } = req.body; // optional: restrict to one gym

      // 1. Get ALL pending_members that have a pdfUrl (inscription complete)
      //    regardless of status — catches pending, awaiting_payment, even converted
      let query = db.collection('pending_members').where('source', '==', 'web');
      if (gymId) query = query.where('gymId', '==', gymId);
      const snap = await query.get();

      const created  = [];
      const updated  = [];
      const skipped  = [];
      const errors   = [];

      for (const doc of snap.docs) {
        const ins       = doc.data();
        const insId     = doc.id;
        const insGymId  = ins.gymId || 'dokarat';
        const fullName  = `${ins.prenom || ''} ${ins.nom || ''}`.trim();

        // Only recover inscriptions that had a PDF generated (= form was completed)
        if (!ins.pdfUrl) {
          skipped.push({ id: insId, name: fullName, reason: 'No PDF — form incomplete' });
          continue;
        }

        try {
          // ── Check if the linked memberId still exists ──────────────────────
          let memberExists = false;
          if (ins.memberId) {
            const mDoc = await db.collection('members').doc(ins.memberId).get();
            if (mDoc.exists && !mDoc.data().deleted && !mDoc.data().isDeleted) {
              memberExists = true;
              // Member exists in Firestore — make sure SQLite cache has it
              try {
                lc.upsertMembers(insGymId, [{ id: ins.memberId, ...mDoc.data() }]);
                updated.push({ id: insId, name: fullName, memberId: ins.memberId, action: 'cache_refreshed' });
              } catch (_) {
                updated.push({ id: insId, name: fullName, memberId: ins.memberId, action: 'cache_refresh_failed' });
              }
              continue;
            }
          }

          // ── Member missing — try dedup before creating ─────────────────────
          let existingMember = null;

          // a) CIN match
          if (!existingMember && ins.cin && ins.cin.trim().length > 3) {
            const cinSnap = await db.collection('members')
              .where('cin', '==', ins.cin.trim().toUpperCase()).limit(1).get();
            if (!cinSnap.empty) existingMember = cinSnap.docs[0];
          }
          // b) Phone match
          if (!existingMember && ins.telephone) {
            const phone = ins.telephone.replace(/\s/g, '');
            if (phone.length >= 9) {
              const pSnap = await db.collection('members').where('phone', '==', phone).limit(1).get();
              if (!pSnap.empty) existingMember = pSnap.docs[0];
            }
          }
          // c) Full-name match
          if (!existingMember && fullName.length > 5) {
            const nSnap = await db.collection('members').where('fullName', '==', fullName).limit(1).get();
            if (!nSnap.empty) existingMember = nSnap.docs[0];
          }

          // ── Derive plan & expiry (same logic as confirm endpoint) ──────────
          const sName = (ins.subscriptionName || '').toLowerCase();
          const monthMatch  = sName.match(/(\d+)\s*mois/);
          const yearMatch   = sName.match(/(\d+)\s*an/);
          const totalMonths = monthMatch ? parseInt(monthMatch[1]) : (yearMatch ? parseInt(yearMatch[1]) * 12 : 1);
          let plan = 'Monthly';
          if      (totalMonths >= 12) plan = 'Annual';
          else if (totalMonths >= 6 ) plan = 'Semi-Annual';
          else if (totalMonths >= 3 ) plan = 'Quarterly';

          let expiresOn = ins.periodTo || null;
          if (!expiresOn) {
            const start = ins.periodFrom ? new Date(ins.periodFrom) : new Date();
            if (ins.durationYears)       start.setFullYear(start.getFullYear() + Number(ins.durationYears));
            else if (ins.durationMonths) start.setMonth(start.getMonth() + Number(ins.durationMonths));
            else                         start.setFullYear(start.getFullYear() + 1);
            expiresOn = start.toISOString().split('T')[0];
          }

          const memberData = {
            fullName,
            phone: ins.telephone || null, plan,
            subscriptionName: ins.subscriptionName || null,
            birthday: ins.dateNaissance || null,
            expiresOn,
            periodFrom: ins.periodFrom || null,
            periodTo:   expiresOn,
            photo: (ins.profilePicture && !ins.profilePicture.startsWith('data:image')) ? ins.profilePicture : null,
            email: ins.email || null,
            cin: ins.cin || null,
            adresse: ins.adresse || null, ville: ins.ville || null,
            location: insGymId,
            contractNumber: ins.contractNumber || null,
            commercial: ins.commercial || null,
            pdfUrl: ins.pdfUrl || null,
            balance: ins.totals?.balance || 0,
            inscriptionId: insId,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            recoveredBy: 'recover-members',
            recoveredAt: admin.firestore.FieldValue.serverTimestamp(),
          };

          let memberId, memberRef;
          if (existingMember) {
            // UPDATE existing — safe merge
            memberId  = existingMember.id;
            memberRef = existingMember.ref;
            await memberRef.update(memberData);
          } else {
            // CREATE new member
            const qrToken = crypto.randomBytes(16).toString('hex');
            memberRef = await db.collection('members').add({
              ...memberData, qrToken,
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
              confirmedBy: 'recover-members',
            });
            memberId = memberRef.id;
          }

          // Link inscription → memberId
          await doc.ref.update({
            memberId,
            status: ins.status === 'pending' ? 'awaiting_payment' : ins.status,
            memberCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
            memberCreatedBy: 'recover-members',
          });

          // Refresh SQLite cache
          const memberSnap = await memberRef.get();
          try { lc.upsertMembers(insGymId, [{ id: memberId, ...memberSnap.data() }]); } catch (_) {}

          // Link orphan payments
          const orphanPay = await db.collection('payments').where('inscriptionId', '==', insId).get();
          for (const p of orphanPay.docs) await p.ref.update({ memberId });

          console.log(`✅ [RECOVER-MEMBERS] ${fullName} | ${insGymId} | ${existingMember ? 'UPDATED' : 'CREATED'} → ${memberId}`);
          created.push({ id: insId, name: fullName, memberId, gymId: insGymId, action: existingMember ? 'updated' : 'created' });

        } catch (e) {
          console.error(`❌ [RECOVER-MEMBERS] ${fullName}:`, e.message);
          errors.push({ id: insId, name: fullName, error: e.message });
        }
      }

      invalidateCache(apiCache.inscriptions);
      res.json({
        ok: true,
        summary: `${created.length} members recovered, ${updated.length} caches refreshed, ${skipped.length} skipped, ${errors.length} errors`,
        created, updated, skipped, errors,
      });
    } catch (err) {
      console.error('Recover Members Error:', err);
      res.status(500).json({ error: 'Recovery failed', detail: err.message });
    }
  });


  router.delete('/api/inscriptions/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('pending_members').doc(req.params.id).delete();
      invalidateCache(apiCache.inscriptions);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete inscription' }); }
  });

  return router;
};
