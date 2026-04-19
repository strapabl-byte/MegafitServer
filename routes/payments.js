'use strict';
// routes/payments.js

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function paymentsRouter({ db, admin, lc, apiCache }) {
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

  // ── GET /api/payments/:memberId ───────────────────────────────────────────
  router.get('/:memberId', verifyAzureToken, async (req, res) => {
    try {
      const snap = await db.collection('payments').where('memberId', '==', req.params.memberId).get();
      let payments = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      payments.sort((a, b) => new Date(b.date || b.createdAt?._seconds * 1000 || 0) - new Date(a.date || a.createdAt?._seconds * 1000 || 0));

      // Virtual backfill: inject registration payment if missing
      if (!payments.some(p => p.type === 'registration')) {
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
              });
            }
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
      const { memberId, amount, plan, date, method, contrat, commercial, location, payments: splitPayments, type, note, reste, balanceDeadline, cin: passedCin, subscriptionName } = req.body;
      let nom = '', tel = '', loc = location || 'dokarat', cin = passedCin || '';
      try {
        const m = await db.collection('members').doc(memberId).get();
        if (m.exists) { 
          nom = m.data().fullName || ''; 
          tel = m.data().phone || ''; 
          loc = location || m.data().location || 'dokarat'; 
          cin = cin || m.data().cin || '';
        }
      } catch (_) {}

      const docRef = await db.collection('payments').add({
        memberId, amount, plan, gymId: loc,
        date: date || new Date().toISOString(),
        method: method || 'Cash',
        type: type || 'renewal',
        note: note || '',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        recordedBy: req.user?.preferred_username || req.user?.name || 'Admin',
      });

      if (memberId && reste !== undefined) {
        await db.collection('members').doc(memberId).update({
          balance: Number(reste) || 0, balanceDeadline: balanceDeadline || null,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      await autoRegisterCA({
        gymId: loc, nom, tel, cin, plan, subscriptionName: subscriptionName || '', amount, method: method || 'Cash',
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
      const gymId      = member.gymId || 'dokarat';
      const contractNum= member.contractNum || '';

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

      // 2. Safely annotate the original register entry 
      if (contractNum) {
        const regSnap = await db.collectionGroup('entries').where('contrat', '==', contractNum).orderBy('createdAt', 'desc').limit(1).get();
        if (!regSnap.empty) {
          const doc = regSnap.docs[0];
          await doc.ref.update({
            reste: newBalance,
            note_reste: newBalance <= 0 ? `✅ Soldé — ${line}` : `⚠️ Reste: ${newBalance} DH\n${line}`,
          });
          
          const updatedReg = await doc.ref.get();
          // Extract the date and gym id from the parent path
          // parent path: megafit_daily_register/dokarat_2026-04-12/entries
          try {
             const parentParts = doc.ref.parent.parent.id.split('_'); // 'dokarat_2026-04-12' -> ['dokarat', '2026-04-12']
             if (parentParts.length === 2) {
                lc.upsertRegister(parentParts[0], parentParts[1], [{ id: doc.id, ...updatedReg.data() }]);
             }
          } catch(e) {}
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

      await db.collection('payments').add({
        inscriptionId, gymId: insData.gymId || 'dokarat',
        amount: Number(amount), plan: plan || 'Monthly',
        date: new Date().toISOString(), method: method || 'Espèces',
        type: 'registration', note: note || '',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        recordedBy: req.user?.preferred_username || 'Admin',
      });

      await autoRegisterCA({
        gymId: insData.gymId || 'dokarat',
        nom: `${insData.prenom || ''} ${insData.nom || ''}`.trim() || fullName || '',
        tel: phone || insData.telephone || '',
        plan: plan || 'Monthly', amount, method: method || 'Espèces',
        commercial: insData.commercial || req.user?.preferred_username || 'FORM',
        contrat: insData.contractNumber || '',
        payments: insData.payments || null,
        reste: insData.totals?.balance || 0, note: note || '',
      });

      if (insDoc.exists) {
        const updateData = { payment_validated: true, updatedAt: admin.firestore.FieldValue.serverTimestamp() };
        if (insData.memberId) {
          const latestPay = await db.collection('payments').where('inscriptionId', '==', inscriptionId).orderBy('createdAt', 'desc').limit(1).get();
          if (!latestPay.empty) await latestPay.docs[0].ref.update({ memberId: insData.memberId });
        }
        await inscriptionRef.update(updateData);
      }

      res.json({ ok: true, message: 'Paiement validé avec succès.' });
    } catch (err) {
      console.error('Complete Inscription Error:', err);
      res.status(500).json({ error: "Échec de l'activation" });
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

  return router;
};
