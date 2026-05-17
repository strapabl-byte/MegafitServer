'use strict';
// routes/payments.js

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function paymentsRouter({ db, admin, lc, apiCache, invalidateCache, uploadBase64ToStorage }) {
  const router = Router();

  // ── Helpers ───────────────────────────────────────────────────────────────
  function planToAbonnement(plan, subscriptionName) {
    // Custom subscription names take priority (e.g. '24 MOIS - LOCAL', '3 MOIS FES')
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
      
      console.log(`✅ AutoRegisterCA: ${nom} | ${prix} DH → ${docId}`);
    } catch (err) {
      console.error('⚠️  AutoRegisterCA (non-blocking):', err.message);
    }
  }

  // ── GET /api/payments/debtors ───────────────────────────────────────────
  // 🔐 Dashboard route: requires Azure token, filters by assigned gym
  router.get('/debtors', verifyAzureToken, async (req, res) => {
    try {
      const isFullAdmin = req.assignedGyms?.includes('all');
      let gymIds = isFullAdmin ? (req.query.gymId || 'all') : req.assignedGyms;
      
      const debtors = lc.getDebtors(gymIds);
      res.json(debtors.map(m => ({
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
    } catch (err) {
      console.error('Debtors Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch debtors' });
    }
  });

  router.get('/public/debtors', async (req, res) => {
    try {
      const gymId = (req.query.gymId || '').toLowerCase().trim();
      const VALID_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });

      // 1. Try SQLite first (unless refresh is requested)
      const refresh = req.query.refresh === 'true';
      const cached = lc.getDebtors(gymId);

      if (cached.length > 0 && !refresh) {
        console.log(`[Debtors] SQLite hit: ${cached.length} debtors for ${gymId}`);
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

      // 2. Firebase fallback/refresh
      console.log(`[Debtors] ${refresh ? 'FORCED REFRESH' : 'SQLite empty'} for ${gymId} — fetching from Firebase`);
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

      // 3. Populate SQLite cache from Firebase results for future calls.
      // CRITICAL: group by member's own gymId, NOT the query gymId, to avoid cross-gym leakage.
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
        console.log(`[Debtors] Firebase fallback: cached ${result.length} debtors to SQLite (by gymId)`);
      }

      res.json(result);
    } catch (err) {
      console.error('Public Debtors Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch debtors' });
    }
  });

  // ── POST /api/payments/settle-member-balance ──────────────────────────────
  router.post('/settle-member-balance', verifyAzureToken, async (req, res) => {
    try {
      const { memberId, amount, method, paymentsSplit, note, chequePhoto, chequePhotoBack, signatureClient, signatureCommercial, commercialName } = req.body;
      if (!memberId || !amount) return res.status(400).json({ error: 'Missing memberId or amount' });

      const memberRef = db.collection('members').doc(memberId);
      const memberSnap = await memberRef.get();
      if (!memberSnap.exists) return res.status(404).json({ error: 'Member not found' });
      
      const member = memberSnap.data();
      const gymId = member.location || member.gymId || 'dokarat';

      // 🔒 SECURITY: Restrict to assigned gyms
      if (!req.hasAccessToGym(gymId)) {
        return res.status(403).json({ error: 'Access Denied: You do not have access to this gym' });
      }

      const oldBalance = Number(member.balance || 0);
      const payAmount = Number(amount);
      const newBalance = Math.max(0, oldBalance - payAmount);

      // Upload images
      let chequeUrl = null, chequeUrlBack = null, sigClientUrl = null, sigCommUrl = null;
      if (chequePhoto) {
        chequeUrl = await uploadBase64ToStorage(chequePhoto, `payments/${memberId}/${Date.now()}_cheque_recto.jpg`);
      }
      if (chequePhotoBack) {
        chequeUrlBack = await uploadBase64ToStorage(chequePhotoBack, `payments/${memberId}/${Date.now()}_cheque_verso.jpg`);
      }
      if (signatureClient) {
        sigClientUrl = await uploadBase64ToStorage(signatureClient, `payments/${memberId}/${Date.now()}_sig_client.png`);
      }
      if (signatureCommercial) {
        sigCommUrl = await uploadBase64ToStorage(signatureCommercial, `payments/${memberId}/${Date.now()}_sig_comm.png`);
      }

      const today = new Date().toISOString().slice(0, 10);
      
      // 1. Create Payment Record
      const payRef = await db.collection('payments').add({
        memberId,
        gymId,
        amount: payAmount,
        method: method || 'Espèces',
        paymentsSplit: paymentsSplit || null,
        date: new Date().toISOString(),
        type: 'balance_settlement',
        note: note || `Règlement reste à payer (Ancien: ${oldBalance} DH, Payé: ${payAmount} DH)`,
        chequePhoto: chequeUrl,
        chequePhotoBack: chequeUrlBack,
        signatureClient: sigClientUrl,
        signatureCommercial: sigCommUrl,
        commercialName: (commercialName || req.user?.name || 'Admin').toUpperCase(),
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        recordedBy: req.user?.preferred_username || 'Admin'
      });

      // 2. Update Member Balance in Firebase
      const updatePayload = {
        balance: newBalance,
        lastPaymentDate: new Date().toISOString(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      };
      // 🧹 Clear the deadline once fully paid
      if (newBalance === 0) updatePayload.balanceDeadline = admin.firestore.FieldValue.delete();
      
      await memberRef.update(updatePayload);

      // 3. Update Daily Register
      await autoRegisterCA({
        gymId,
        date: today,
        nom: member.fullName || '',
        tel: member.phone || '',
        cin: member.cin || '',
        plan: member.plan || 'Monthly',
        subscriptionName: member.subscriptionName || '',
        amount: payAmount,
        method: method || 'Espèces',
        payments: paymentsSplit,
        commercial: commercialName || req.user?.name || 'Admin',
        contrat: member.contractNumber || '',
        reste: newBalance,
        note: `Règlement Reste [${member.fullName}]`
      });

      // 4. Update local cache
      const updatedMemberSnap = await memberRef.get();
      lc.upsertMembers(gymId, [{ id: memberId, ...updatedMemberSnap.data() }]);
      // autoRegisterCA already handles SQLite register update

      res.json({ ok: true, paymentId: payRef.id, newBalance });
    } catch (err) {
      console.error('Settle Member Balance Error:', err);
      res.status(500).json({ error: 'Failed to settle balance' });
    }
  });

  // ── GET /api/payments/:memberId ───────────────────────────────────────────
  router.get('/:memberId', verifyAzureToken, async (req, res) => {
    try {
      const snap = await db.collection('payments').where('memberId', '==', req.params.memberId).get();
      let payments = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin) {
          const assigned = req.assignedGyms?.[0];
          let gymId;
          if (assigned && assigned !== 'all') {
              gymId = assigned;
          } else {
              gymId = 'none';
          }
          const diskMember = lc.getMemberById ? lc.getMemberById(req.params.memberId) : null;
          if (diskMember && diskMember.gym_id && !req.hasAccessToGym(diskMember.gym_id)) {
              return res.status(403).json({ error: 'Access Denied: This member belongs to another gym' });
          }
      }

      payments.sort((a, b) => new Date(b.date || b.createdAt?._seconds * 1000 || 0) - new Date(a.date || a.createdAt?._seconds * 1000 || 0));

      // Virtual backfill: inject registration payment if missing
      // 🔒 DISK-FIRST: Read member + inscription from SQLite, not Firebase.
      if (!payments.some(p => p.type === 'registration')) {
        // Try SQLite disk first
        const diskMember = lc.getMemberById ? lc.getMemberById(req.params.memberId) : null;
        const diskMemberData = diskMember || null;
        const inscriptionId = diskMemberData?.inscriptionId || diskMemberData?.inscription_id || null;

        if (inscriptionId) {
          // Try SQLite pending_members
          const diskIns = lc.getPendingById ? lc.getPendingById(inscriptionId) : null;
          if (diskIns) {
            const totalPaid = Number(diskIns.totals?.paid || (typeof diskIns.totals === 'string' ? JSON.parse(diskIns.totals)?.paid : 0)) ||
              ((Number(diskIns.payments?.espece   || 0)) +
               (Number(diskIns.payments?.tpe      || diskIns.payments?.carte || 0)) +
               (Number(diskIns.payments?.virement || 0)) +
               (Number(diskIns.payments?.cheque   || 0)));
            const parsedPayments = typeof diskIns.payments === 'string' ? JSON.parse(diskIns.payments || '{}') : (diskIns.payments || {});
            if (totalPaid > 0) {
              const methods = [];
              if (Number(parsedPayments.espece)                              > 0) methods.push('Esp');
              if (Number(parsedPayments.carte || parsedPayments.tpe)        > 0) methods.push('Car');
              if (Number(parsedPayments.cheque)                             > 0) methods.push('Chq');
              if (Number(parsedPayments.virement)                           > 0) methods.push('Vir');
              payments.push({
                id: `reg-${inscriptionId}`, amount: totalPaid,
                plan: diskMemberData.plan || 'Monthly',
                date: diskMemberData.createdAt || diskMemberData.created_at || new Date().toISOString(),
                method: methods.join('+') || 'Dépôt',
                type: 'registration', note: 'Paiement inscription initiale', virtual: true,
                pdfUrl: diskIns.pdfUrl || diskIns.pdf_url || diskMemberData.pdfUrl || null,
                contractNumber: diskIns.contractNumber || diskIns.contract_number || diskMemberData.contractNumber || null,
                subscriptionName: diskIns.subscriptionName || diskIns.subscription_name || diskMemberData.plan || null,
                chequePhoto: diskIns.cheque_photo || diskIns.chequePhoto || null,
                chequePhotoBack: diskIns.cheque_photo_back || diskIns.chequePhotoVerso || diskIns.chequePhotoBack || null,
              });
            }
          } else {
            // Firebase fallback: only if not on disk
            try {
              const mSnap = diskMemberData
                ? { exists: true, data: () => diskMemberData }
                : await db.collection('members').doc(req.params.memberId).get();
              if (mSnap.exists && mSnap.data().inscriptionId) {
                const insSnap = await db.collection('pending_members').doc(mSnap.data().inscriptionId).get();
                if (insSnap.exists) {
                  const ins = insSnap.data();
                  const m   = mSnap.data();
                  const totalPaid = Number(ins.totals?.paid) ||
                    ((Number(ins.payments?.espece   ) || 0) +
                     (Number(ins.payments?.tpe      ) || 0) +
                     (Number(ins.payments?.carte    ) || 0) +
                     (Number(ins.payments?.virement ) || 0) +
                     (Number(ins.payments?.cheque   ) || 0));
                  if (totalPaid > 0) {
                    const methods = [];
                    if (Number(ins.payments?.espece                     ) > 0) methods.push('Esp');
                    if (Number(ins.payments?.carte || ins.payments?.tpe ) > 0) methods.push('Car');
                    if (Number(ins.payments?.cheque                     ) > 0) methods.push('Chq');
                    if (Number(ins.payments?.virement                   ) > 0) methods.push('Vir');
                    payments.push({
                      id: `reg-${m.inscriptionId}`, amount: totalPaid,
                      plan: m.plan || 'Monthly',
                      date: m.createdAt?._seconds ? new Date(m.createdAt._seconds * 1000).toISOString() : new Date().toISOString(),
                      method: methods.join('+') || 'Dépôt',
                      type: 'registration', note: 'Paiement inscription initiale', virtual: true,
                      pdfUrl: ins.pdfUrl || m.pdfUrl || null,
                      contractNumber: ins.contractNumber || m.contractNumber || null,
                      subscriptionName: ins.subscriptionName || m.plan || null,
                      chequePhoto: ins.chequePhoto || ins.cheque_photo || null,
                      chequePhotoBack: ins.chequePhotoVerso || ins.chequePhotoBack || ins.cheque_photo_back || null,
                    });
                  }
                }
              }
            } catch (fbErr) {
              console.warn('[PAYMENTS GET] inscription Firebase fallback failed:', fbErr.message);
            }
          }
        } else if (!diskMemberData) {
          // No disk record at all — full Firebase fallback
          try {
            const mSnap = await db.collection('members').doc(req.params.memberId).get();
            if (mSnap.exists && mSnap.data().inscriptionId) {
              const insSnap = await db.collection('pending_members').doc(mSnap.data().inscriptionId).get();
              if (insSnap.exists) {
                const ins = insSnap.data();
                const m   = mSnap.data();
                const totalPaid = Number(ins.totals?.paid) ||
                  ((Number(ins.payments?.espece   ) || 0) +
                   (Number(ins.payments?.tpe      ) || 0) +
                   (Number(ins.payments?.carte    ) || 0) +
                   (Number(ins.payments?.virement ) || 0) +
                   (Number(ins.payments?.cheque   ) || 0));
                if (totalPaid > 0) {
                  const methods = [];
                  if (Number(ins.payments?.espece                     ) > 0) methods.push('Esp');
                  if (Number(ins.payments?.carte || ins.payments?.tpe ) > 0) methods.push('Car');
                  if (Number(ins.payments?.cheque                     ) > 0) methods.push('Chq');
                  if (Number(ins.payments?.virement                   ) > 0) methods.push('Vir');
                  payments.push({
                    id: `reg-${m.inscriptionId}`, amount: totalPaid,
                    plan: m.plan || 'Monthly',
                    date: m.createdAt?._seconds ? new Date(m.createdAt._seconds * 1000).toISOString() : new Date().toISOString(),
                    method: methods.join('+') || 'Dépôt',
                    type: 'registration', note: 'Paiement inscription initiale', virtual: true,
                    pdfUrl: ins.pdfUrl || m.pdfUrl || null,
                    contractNumber: ins.contractNumber || m.contractNumber || null,
                    subscriptionName: ins.subscriptionName || m.plan || null,
                    chequePhoto: ins.chequePhoto || ins.cheque_photo || null,
                    chequePhotoBack: ins.chequePhotoVerso || ins.chequePhotoBack || ins.cheque_photo_back || null,
                  });
                }
              }
            }
          } catch (fbErr) {
            console.warn('[PAYMENTS GET] full Firebase fallback failed:', fbErr.message);
          }
        }
      }

      res.json(payments);
    } catch (err) {
      console.error('Payment History Error:', err);
      res.status(500).json({ error: 'Failed to fetch payments' });
    }
  });

  // ── POST /api/payments ────────────────────────────────────────────────────
  router.post('/', verifyAzureToken, async (req, res) => {
    try {
      const { memberId, amount, plan, date, method, contrat, commercial, location, payments: splitPayments, type, note, reste, balanceDeadline, cin: passedCin, subscriptionName, inscriptionId } = req.body;
      
      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin && location && !req.hasAccessToGym(location)) {
          return res.status(403).json({ error: 'Access Denied: You cannot record payments for another gym' });
      }
      
      let nom = '', tel = '', loc = location || 'dokarat', cin = passedCin || '';
      try {
        // 🔒 DISK-FIRST: Read member data from SQLite, not Firebase
        const diskMember = lc.getMemberById ? lc.getMemberById(memberId) : null;
        if (diskMember) {
          nom = diskMember.fullName || diskMember.full_name || '';
          tel = diskMember.phone || '';
          loc = location || diskMember.location || 'dokarat';
          cin = cin || diskMember.cin || '';
        } else {
          const m = await db.collection('members').doc(memberId).get();
          if (m.exists) {
            nom = m.data().fullName || '';
            tel = m.data().phone || '';
            loc = location || m.data().location || 'dokarat';
            cin = cin || m.data().cin || '';
          }
        }
      } catch (_) {}

      let docRef;
      // ✅ ANTI-DUP LOGIC: If this is an inscription confirmation, check if the payment record was already pre-created
      if (inscriptionId && type === 'registration') {
        const existing = await db.collection('payments').where('inscriptionId', '==', inscriptionId).limit(1).get();
        if (!existing.empty) {
          docRef = existing.docs[0].ref;
          await docRef.update({
            amount, plan, gymId: loc,
            date: date || new Date().toISOString(),
            method: method || 'Cash',
            type: 'registration',
            note: note || '',
            paymentsSplit: splitPayments || null,
            recordedBy: req.user?.preferred_username || req.user?.name || 'Admin',
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          });
          console.log(`♻️ Updated existing registration payment for inscription: ${inscriptionId}`);
        }
      }

      if (!docRef) {
        docRef = await db.collection('payments').add({
          memberId, amount, plan, gymId: loc,
          date: date || new Date().toISOString(),
          method: method || 'Cash',
          type: type || 'renewal',
          note: note || '',
          paymentsSplit: splitPayments || null,
          inscriptionId: inscriptionId || null,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          recordedBy: req.user?.preferred_username || req.user?.name || 'Admin',
        });
      }

      if (memberId && reste !== undefined) {
        await db.collection('members').doc(memberId).update({
          balance: Number(reste) || 0, balanceDeadline: balanceDeadline || null,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      // ── Resolve register date: use inscription createdAt if this is a registration payment ──
      // This ensures the register entry lands on the day the inscription was submitted,
      // not the day the admin confirms it (which may be days later).
      let registerDate = date || null;
      if (!registerDate && inscriptionId && type === 'registration') {
        try {
          const diskIns = lc.getPendingById ? lc.getPendingById(inscriptionId) : null;
          if (diskIns?.createdAt) {
            registerDate = new Date(diskIns.createdAt).toISOString().slice(0, 10);
          } else {
            const insDoc = await db.collection('pending_members').doc(inscriptionId).get();
            if (insDoc.exists && insDoc.data().createdAt?._seconds) {
              registerDate = new Date(insDoc.data().createdAt._seconds * 1000).toISOString().slice(0, 10);
            }
          }
        } catch (_) {}
      }

      await autoRegisterCA({
        gymId: loc, date: registerDate, nom, tel, cin, plan, subscriptionName: subscriptionName || '', amount, method: method || 'Cash',
        commercial: commercial || req.user?.preferred_username || 'Admin',
        contrat: contrat || '', payments: splitPayments,
        reste: reste || 0, note: note || '',
      });

      const snap = await docRef.get();
      res.json({ id: docRef.id, ...snap.data() });
    } catch (err) {
      console.error('Payment Record Error:', err);
      res.status(500).json({ error: 'Failed to record payment' });
    }
  });

  // ── POST /api/payments/settle-balance ─────────────────────────────────────
  router.post('/settle-balance', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { memberId, amount, method, note, balanceDeadline } = req.body;
      if (!amount || !memberId) return res.status(400).json({ error: 'Missing reqs' });

      const memberRef  = db.collection('members').doc(memberId);
      const memberSnap = await memberRef.get();

      if (!memberSnap.exists) return res.status(404).json({ error: 'Membre introuvable' });

      const member     = memberSnap.data();
      const oldBalance = Number(member.balance || 0);
      const payAmount  = Number(amount);
      const newBalance = Math.max(0, oldBalance - payAmount);
      const gymId      = member.location || member.gymId || 'dokarat'; // ✅ Fixed: was member.gymId (always undefined)
      const contractNum= member.contractNumber || member.contractNum || ''; // ✅ Fixed: was member.contractNum

      await db.collection('payments').add({
        memberId, gymId, amount: payAmount, plan: member.plan || 'Monthly',
        date: new Date().toISOString(), method: method || 'Espèces',
        note: note || `Complément — reste initial: ${oldBalance} DH`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        recordedBy: req.user?.preferred_username || 'Admin',
        type: 'balance_settlement',
      });

      await memberRef.update({ balance: newBalance, balanceDeadline: balanceDeadline || null, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      
      const updatedMember = await memberRef.get();
      lc.upsertMembers(gymId, [{ id: memberId, ...updatedMember.data() }]);

      // 1. Add the cash to TODAY's register so the drawer balances at end of day
      const dateStr = new Date().toLocaleDateString('fr-FR');
      const line    = `+ ${payAmount} DH (${method || 'Espèces'}) le ${dateStr}`;
      
      await autoRegisterCA({
        gymId, nom: memberSnap.data().fullName || 'Inconnu',
        tel: member.phone || '', plan: member.plan || 'Monthly',
        amount: payAmount, method: method || 'Espèces',
        commercial: req.user?.preferred_username || 'Admin',
        contrat: contractNum, reste: newBalance,
        note: note || `Complément encaissé aujourd'hui (Reste: ${newBalance} DH)`
      });

      // 🔒 DISK-FIRST: Search register_cache in SQLite by contract number
      if (contractNum) {
        const regRows = lc.db ? lc.db.prepare(`
          SELECT * FROM register_cache WHERE contrat = ? ORDER BY date DESC LIMIT 1
        `).all(contractNum) : [];
        if (regRows.length > 0) {
          const row = regRows[0];
          const line = `+ ${payAmount} DH (${method || 'Espèces'}) le ${new Date().toLocaleDateString('fr-FR')}`;
          const updatedReste = newBalance <= 0 ? `✅ Soldé — ${line}` : `⚠️ Reste: ${newBalance} DH\n${line}`;
          // Update SQLite
          try { lc.db.prepare('UPDATE register_cache SET reste = ?, note_reste = ? WHERE id = ? AND gym_id = ?')
            .run(newBalance, updatedReste, row.id, row.gym_id); } catch(_) {}
          // Also update Firebase in background (non-blocking)
          try {
            const fbRef = db.collection('megafit_daily_register').doc(`${row.gym_id}_${row.date}`).collection('entries').doc(row.id);
            fbRef.update({ reste: newBalance, note_reste: updatedReste }).catch(() => {});
          } catch(_) {}
        }
      }

      res.json({ ok: true, newBalance, message: `Complément enregistré. Nouveau reste: ${newBalance} DH` });
    } catch (err) {
      console.error('Settle Balance Error:', err);
      res.status(500).json({ error: 'Failed to settle balance' });
    }
  });

  // ── POST /api/payments/complete-inscription ───────────────────────────────
  router.post('/complete-inscription', verifyAzureToken, async (req, res) => {
    try {
      const { inscriptionId, amount, plan, method, fullName, phone, note } = req.body;
      const inscriptionRef = db.collection('pending_members').doc(inscriptionId);
      const insDoc = await inscriptionRef.get();
      const insData = insDoc.exists ? insDoc.data() : { telephone: phone };

      // 🛡️ ANTI-DUP: Check if payment already recorded for this inscription
      const existingPay = await db.collection('payments').where('inscriptionId', '==', inscriptionId).limit(1).get();
      if (existingPay.empty) {
        await db.collection('payments').add({
          inscriptionId, gymId: insData.gymId || 'dokarat',
          amount: Number(amount), plan: plan || 'Monthly',
          date: new Date().toISOString(), method: method || 'Espèces',
          type: 'registration', note: note || '',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          recordedBy: req.user?.preferred_username || 'Admin',
        });
      } else {
        await existingPay.docs[0].ref.update({
          amount: Number(amount), plan: plan || 'Monthly',
          method: method || 'Espèces',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          recordedBy: req.user?.preferred_username || 'Admin',
        });
        console.log(`♻️ Updated existing payment record for inscription: ${inscriptionId}`);
      }

      // ── Resolve register date: use inscription's original createdAt ──────────
      let registerDate2 = null;
      if (insDoc.exists && insData.createdAt?._seconds) {
        registerDate2 = new Date(insData.createdAt._seconds * 1000).toISOString().slice(0, 10);
      }

      await autoRegisterCA({
        gymId: insData.gymId || 'dokarat',
        date: registerDate2, // use inscription creation date, not today
        nom: `${insData.prenom || ''} ${insData.nom || ''}`.trim() || fullName || '',
        tel: phone || insData.telephone || '',
        plan: plan || 'Monthly', amount, method: method || 'Espèces',
        commercial: insData.commercial || req.user?.preferred_username || 'FORM',
        contrat: insData.contractNumber || '',
        payments: insData.payments || null,
        reste: insData.totals?.balance || 0, note: note || '',
      });

      if (insDoc.exists) {
        const updateData = { 
          status: 'converted', 
          payment_validated: true, 
          updatedAt: admin.firestore.FieldValue.serverTimestamp() 
        };
        if (insData.memberId) {
          const latestPay = await db.collection('payments').where('inscriptionId', '==', inscriptionId).orderBy('createdAt', 'desc').limit(1).get();
          if (!latestPay.empty) await latestPay.docs[0].ref.update({ memberId: insData.memberId });
        }
        await inscriptionRef.update(updateData);
      }

      // invalidate cache so it doesn't show as awaiting_payment anymore
      if (invalidateCache && apiCache) {
        invalidateCache(apiCache.inscriptions);
      }

      res.json({ ok: true, message: 'Paiement validé avec succès.' });
    } catch (err) {
      console.error('Complete Inscription Error:', err);
      res.status(500).json({ error: "Échec de l'activation" });
    }
  });

  // ── POST /api/payments/:id/replay-to-register ────────────────────────────
  // 🛡️ Super Admin only — Force-injects a payment that exists in Firestore
  // but is missing from the Daily Register (megafit_daily_register).
  router.post('/:id/replay-to-register', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const paymentRef = db.collection('payments').doc(req.params.id);
      const paymentDoc = await paymentRef.get();
      if (!paymentDoc.exists) return res.status(404).json({ error: 'Paiement introuvable' });
      const payment = paymentDoc.data();

      // ── GUARD 1 (hard): payment already stamped as replayed ──────────────
      if (payment.replayedToRegister) {
        return res.status(409).json({
          error: `Paiement déjà injecté dans le registre le ${payment.replayedAt ? new Date(payment.replayedAt).toLocaleDateString('fr-MA') : '?'} par ${payment.replayedBy || 'Admin'}. Opération bloquée.`,
          alreadyReplayed: true,
        });
      }

      // ── Enrich with member data ──────────────────────────────────────────
      let nom = payment.nom || '', tel = '', cin = '', contrat = '', commercial = 'Admin';
      const gymId = payment.gymId || payment.location || 'dokarat';
      if (payment.memberId) {
        const mSnap = await db.collection('members').doc(payment.memberId).get();
        if (mSnap.exists) {
          const m = mSnap.data();
          nom        = m.fullName  || nom;
          tel        = m.phone     || '';
          cin        = m.cin       || '';
          contrat    = m.contractNumber || payment.contrat || '';
          commercial = payment.commercial || m.commercial || 'Admin';
        }
      }

      // ── Resolve date ─────────────────────────────────────────────────────
      let dateStr = req.body.date || null;
      if (!dateStr) {
        let dateObj = new Date();
        if (payment.date) {
          dateObj = typeof payment.date === 'string' ? new Date(payment.date) : payment.date.toDate?.() ?? new Date();
        } else if (payment.createdAt?._seconds) {
          dateObj = new Date(payment.createdAt._seconds * 1000);
        }
        dateStr = dateObj.toISOString().slice(0, 10);
      }

      // ── GUARD 2 (hard): fuzzy name+amount match in register ─────────────
      const regDocId = `${gymId}_${dateStr}`;
      const amount   = Number(payment.amount) || 0;
      const existingSnap = await db.collection('megafit_daily_register')
        .doc(regDocId).collection('entries')
        .where('prix', '==', amount)
        .get();
      if (!existingSnap.empty) {
        const firstName = nom.toLowerCase().trim().split(' ')[0];
        const match = existingSnap.docs.find(d => {
          const enom = (d.data().nom || '').toLowerCase().trim();
          return enom.includes(firstName) || firstName.includes(enom.split(' ')[0]);
        });
        if (match) {
          return res.status(409).json({
            error: `${nom} est déjà présent dans le registre du ${dateStr} pour ${amount} DH. Injection bloquée.`,
            alreadyInRegister: true,
          });
        }
      }

      // ── Inject into register ─────────────────────────────────────────────
      await autoRegisterCA({
        gymId, date: dateStr, nom, tel, cin,
        plan:             payment.plan,
        subscriptionName: payment.subscriptionName || '',
        amount,
        method:           payment.method || 'Espèces',
        commercial:       req.user?.preferred_username || commercial,
        contrat,
        payments:         payment.paymentsSplit || null,
        reste:            0,
        note:             `[REPLAY] ${payment.note || 'Paiement rejoué par Super Admin'}`,
      });

      // ── Stamp the payment to permanently lock the replay button ──────────
      await paymentRef.update({
        replayedToRegister: true,
        replayedAt:  new Date().toISOString(),
        replayedBy:  req.user?.preferred_username || req.user?.name || 'Admin',
      });

      console.log(`🔁 [REPLAY] ${nom} | ${amount} DH | ${gymId}_${dateStr} — by ${req.user?.preferred_username}`);
      res.json({ ok: true, message: `✅ Paiement de ${nom} injecté dans le registre du ${dateStr}. Bouton verrouillé.`, date: dateStr });
    } catch (err) {
      console.error('Replay Register Error:', err);
      res.status(500).json({ error: 'Échec du replay' });
    }
  });

  // ── DELETE /api/payments/:id ──────────────────────────────────────────────
  router.delete('/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const paymentRef = db.collection('payments').doc(req.params.id);
      const paymentDoc = await paymentRef.get();
      if (!paymentDoc.exists) return res.status(404).json({ error: 'Payment not found' });
      const payment = paymentDoc.data();
      
      const gymId = payment.gymId || 'dokarat';
      const amount = Number(payment.amount) || 0;
      const memberId = payment.memberId;

      // 1. Revert member balance if it was a complement
      if (payment.type === 'balance_settlement' && memberId) {
        const memberRef = db.collection('members').doc(memberId);
        const memberDoc = await memberRef.get();
        if (memberDoc.exists) {
          const currentBalance = Number(memberDoc.data().balance) || 0;
          await memberRef.update({ balance: currentBalance + amount, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
        }
      }

      // 2. Try to find and delete the daily register entry
      // Date can be an ISO string or a Firestore Timestamp
      let dateObj = new Date();
      if (payment.date) {
        dateObj = typeof payment.date === 'string' ? new Date(payment.date) : payment.date.toDate();
      } else if (payment.createdAt) {
        dateObj = payment.createdAt.toDate();
      }
      const dateStr = dateObj.toISOString().slice(0, 10);
      const regDocId = `${gymId}_${dateStr}`;
      
      const entriesRef = db.collection('megafit_daily_register').doc(regDocId).collection('entries');
      const entriesSnap = await entriesRef.where('prix', '==', amount).get();
      
      let matchedEntryId = null;
      if (!entriesSnap.empty) {
        // If there's multiple, let's try to match by exact plan string, or method
        let matches = entriesSnap.docs;
        if (matches.length > 1) {
          const paymentMethod = (payment.method || '').toLowerCase();
          matches = matches.filter(d => {
             const e = d.data();
             const hasEspece = paymentMethod.includes('esp') && Number(e.espece) > 0;
             const hasTPE = paymentMethod.includes('carte') && Number(e.tpe) > 0;
             const hasCheque = paymentMethod.includes('chèq') && Number(e.cheque) > 0;
             const hasVirement = paymentMethod.includes('vir') && Number(e.virement) > 0;
             return hasEspece || hasTPE || hasCheque || hasVirement;
          });
        }
        if (matches.length > 0) {
          matchedEntryId = matches[0].id;
          await matches[0].ref.delete();
          // Clear SQLite register cache
          lc.deleteRegisterEntry(gymId, dateStr, matchedEntryId);
        }
      }

      // 3. Delete the payment itself
      await paymentRef.delete();
      lc.deletePayment(gymId, req.params.id);

      res.json({ ok: true, message: 'Paiement supprimé', registerCleaned: !!matchedEntryId });
    } catch (err) {
      console.error('Delete Payment Error:', err);
      res.status(500).json({ error: 'Failed to delete payment' });
    }
  });

  // ── PATCH /api/payments/:id/cheque-photos  ────────────────────────────────
  // Super-admin: inject / replace cheque recto+verso photos on an existing payment.
  // Uploads base64 images to Firebase Storage, updates Firestore payment doc,
  // and stores the public URLs in pending_cache for SQLite reference.
  router.patch('/:id/cheque-photos', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const paymentId = req.params.id;
      const { chequePhoto, chequePhotoBack, memberId } = req.body;

      if (!chequePhoto && !chequePhotoBack) {
        return res.status(400).json({ error: 'At least one photo (chequePhoto or chequePhotoBack) is required' });
      }

      if (paymentId.startsWith('reg-')) {
        const inscriptionId = paymentId.replace('reg-', '');
        const inscriptionRef = db.collection('pending_members').doc(inscriptionId);
        const insSnap = await inscriptionRef.get();
        if (!insSnap.exists) return res.status(404).json({ error: 'Payment not found (Virtual inscription not found)' });

        const ts  = Date.now();
        const mid = memberId || insSnap.data().memberId || 'unknown';
        const update = {};

        if (chequePhoto) {
          const url = await uploadBase64ToStorage(chequePhoto, `payments/${mid}/${ts}_cheque_recto.jpg`);
          update.chequePhoto = url;
        }
        if (chequePhotoBack) {
          const url = await uploadBase64ToStorage(chequePhotoBack, `payments/${mid}/${ts}_cheque_verso.jpg`);
          update.chequePhotoBack = url;
        }

        update.chequePhotoUpdatedAt = admin.firestore.FieldValue.serverTimestamp();
        update.chequePhotoUpdatedBy = req.user?.preferred_username || req.user?.name || 'Admin';
        await inscriptionRef.update(update);

        // Also update local SQLite pending cache so it's instantly synchronized!
        try {
          if (lc.updatePendingChequePhotos) {
            lc.updatePendingChequePhotos(inscriptionId, update.chequePhoto, update.chequePhotoBack);
          }
        } catch (sqliteErr) {
          console.error('Failed to update SQLite pending cache:', sqliteErr);
        }

        return res.json({ ok: true, chequePhoto: update.chequePhoto || null, chequePhotoBack: update.chequePhotoBack || null });
      }

      const paymentRef = db.collection('payments').doc(paymentId);
      const paySnap    = await paymentRef.get();
      if (!paySnap.exists) return res.status(404).json({ error: 'Payment not found' });

      const ts  = Date.now();
      const mid = memberId || paySnap.data().memberId || 'unknown';
      const update = {};

      if (chequePhoto) {
        const url = await uploadBase64ToStorage(chequePhoto, `payments/${mid}/${ts}_cheque_recto.jpg`);
        update.chequePhoto = url;
        console.log(`📸 [cheque-photos] Recto uploaded for payment ${paymentId}: ${url}`);
      }
      if (chequePhotoBack) {
        const url = await uploadBase64ToStorage(chequePhotoBack, `payments/${mid}/${ts}_cheque_verso.jpg`);
        update.chequePhotoBack = url;
        console.log(`📸 [cheque-photos] Verso uploaded for payment ${paymentId}: ${url}`);
      }

      update.chequePhotoUpdatedAt = admin.firestore.FieldValue.serverTimestamp();
      update.chequePhotoUpdatedBy = req.user?.preferred_username || req.user?.name || 'Admin';
      await paymentRef.update(update);

      res.json({ ok: true, chequePhoto: update.chequePhoto || null, chequePhotoBack: update.chequePhotoBack || null });
    } catch (err) {
      console.error('Cheque photo upload error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
