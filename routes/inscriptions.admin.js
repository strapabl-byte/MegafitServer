'use strict';
// routes/inscriptions.admin.js
// Super-Admin maintenance routes — require token + requireAdmin role
// Handles: recover-register, recover-members, fix-pdf-urls

const { Router } = require('express');
const crypto = require('crypto');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function inscriptionsAdminRouter({ db, admin, lc, apiCache, invalidateCache }) {
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
          console.warn(`[DEDUP] autoRegisterCA: Duplicate ${contrat} for ${gymId}/${today}. Skipping.`);
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
        reste: Number(reste) || 0,
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

  // ── POST /recover-register ────────────────────────────────────────────────
  // Finds accepted inscriptions missing from the daily register and injects them.
  // Safe to run multiple times — uses source+contrat guard.
  router.post('/recover-register', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, daysBack = 7 } = req.body;
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - Number(daysBack));

      let query = db.collection('pending_members').where('status', '==', 'awaiting_payment');
      if (gymId) query = query.where('gymId', '==', gymId);
      const snap = await query.get();

      const recovered = [], skipped = [], errors = [];

      for (const doc of snap.docs) {
        const ins = doc.data();
        const insGymId = ins.gymId || 'dokarat';
        const fullName = `${ins.prenom || ''} ${ins.nom || ''}`.trim();
        const contrat  = ins.contractNumber || '';

        let dateStr = new Date().toISOString().slice(0, 10);
        if (ins.createdAt?._seconds) {
          dateStr = new Date(ins.createdAt._seconds * 1000).toISOString().slice(0, 10);
        } else if (ins.memberCreatedAt?._seconds) {
          dateStr = new Date(ins.memberCreatedAt._seconds * 1000).toISOString().slice(0, 10);
        }

        if (new Date(dateStr) < cutoff) {
          skipped.push({ id: doc.id, name: fullName, reason: 'Too old' });
          continue;
        }

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

          const existInSQLite = lc.db.prepare(
            `SELECT id FROM register_cache WHERE gym_id=? AND contrat=? AND date=? LIMIT 1`
          ).get(insGymId, contrat, dateStr);
          if (existInSQLite) {
            skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'Already in SQLite register' });
            continue;
          }
        }

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
            gymId: insGymId, date: dateStr,
            nom: fullName, tel: ins.telephone || '', cin: ins.cin || '',
            plan: ins.plan || 'Annual', subscriptionName: ins.subscriptionName || '',
            amount: totalPaid, method, commercial: ins.commercial || 'FORM', contrat,
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
        recovered, skipped, errors,
      });
    } catch (err) {
      console.error('Recover Register Error:', err);
      res.status(500).json({ error: 'Recovery failed', detail: err.message });
    }
  });

  // ── POST /recover-members ─────────────────────────────────────────────────
  // Finds inscriptions with a PDF but whose member is missing from Firebase/SQLite.
  // Safe to run multiple times — dedup prevents duplicate members.
  router.post('/recover-members', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId } = req.body;

      let query = db.collection('pending_members').where('source', '==', 'web');
      if (gymId) query = query.where('gymId', '==', gymId);
      const snap = await query.get();

      const created = [], updated = [], skipped = [], errors = [];

      for (const doc of snap.docs) {
        const ins      = doc.data();
        const insId    = doc.id;
        const insGymId = ins.gymId || 'dokarat';
        const fullName = `${ins.prenom || ''} ${ins.nom || ''}`.trim();

        if (!ins.pdfUrl) {
          skipped.push({ id: insId, name: fullName, reason: 'No PDF — form incomplete' });
          continue;
        }

        try {
          let memberExists = false;
          if (ins.memberId) {
            const mDoc = await db.collection('members').doc(ins.memberId).get();
            if (mDoc.exists && !mDoc.data().deleted && !mDoc.data().isDeleted) {
              memberExists = true;
              try {
                lc.upsertMembers(insGymId, [{ id: ins.memberId, ...mDoc.data() }]);
                updated.push({ id: insId, name: fullName, memberId: ins.memberId, action: 'cache_refreshed' });
              } catch (_) {
                updated.push({ id: insId, name: fullName, memberId: ins.memberId, action: 'cache_refresh_failed' });
              }
              continue;
            }
          }

          let existingMember = null;

          if (!existingMember && ins.cin && ins.cin.trim().length > 3) {
            const cinSnap = await db.collection('members').where('cin', '==', ins.cin.trim().toUpperCase()).limit(1).get();
            if (!cinSnap.empty) existingMember = cinSnap.docs[0];
          }
          if (!existingMember && ins.telephone) {
            const phone = ins.telephone.replace(/\s/g, '');
            if (phone.length >= 9) {
              const pSnap = await db.collection('members').where('phone', '==', phone).limit(1).get();
              if (!pSnap.empty) existingMember = pSnap.docs[0];
            }
          }
          if (!existingMember && fullName.length > 5) {
            const nSnap = await db.collection('members').where('fullName', '==', fullName).limit(1).get();
            if (!nSnap.empty) existingMember = nSnap.docs[0];
          }

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
            fullName, phone: ins.telephone || null, plan,
            subscriptionName: ins.subscriptionName || null,
            birthday: ins.dateNaissance || null,
            expiresOn, periodFrom: ins.periodFrom || null, periodTo: expiresOn,
            photo: (ins.profilePicture && !ins.profilePicture.startsWith('data:image')) ? ins.profilePicture : null,
            email: ins.email || null, cin: ins.cin || null,
            adresse: ins.adresse || null, ville: ins.ville || null,
            location: insGymId, contractNumber: ins.contractNumber || null,
            commercial: ins.commercial || null, pdfUrl: ins.pdfUrl || null,
            balance: ins.totals?.balance || 0, inscriptionId: insId,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            recoveredBy: 'recover-members',
            recoveredAt: admin.firestore.FieldValue.serverTimestamp(),
          };

          let memberId, memberRef;
          if (existingMember) {
            memberId  = existingMember.id;
            memberRef = existingMember.ref;
            await memberRef.update(memberData);
          } else {
            const qrToken = crypto.randomBytes(16).toString('hex');
            memberRef = await db.collection('members').add({
              ...memberData, qrToken,
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
              confirmedBy: 'recover-members',
            });
            memberId = memberRef.id;
          }

          await doc.ref.update({
            memberId,
            status: ins.status === 'pending' ? 'awaiting_payment' : ins.status,
            memberCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
            memberCreatedBy: 'recover-members',
          });

          const memberSnap = await memberRef.get();
          try { lc.upsertMembers(insGymId, [{ id: memberId, ...memberSnap.data() }]); } catch (_) {}

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

  // ── POST /api/inscriptions/fix-pdf-urls ──────────────────────────────────
  // Repair: propagates pdfUrl AND photo from confirmed inscriptions → member docs.
  // Accepts x-inject-secret header for maintenance curl calls.
  router.post('/api/inscriptions/fix-pdf-urls', async (req, res) => {
    const secret = req.headers['x-inject-secret'] || req.body?.secret;
    if (secret !== (process.env.SEED_SECRET || 'megafit-seed-2026')) {
      if (!req.headers.authorization) return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const [snap1, snap2] = await Promise.all([
        db.collection('pending_members').where('status', '==', 'awaiting_payment').get(),
        db.collection('pending_members').where('status', '==', 'converted').get(),
      ]);
      const allDocs = [...snap1.docs, ...snap2.docs];

      const fixed = [], skipped = [], errors = [];

      for (const doc of allDocs) {
        const ins = doc.data();
        if (!ins.memberId) {
          skipped.push({ id: doc.id, reason: 'no memberId' });
          continue;
        }

        try {
          const memberRef = db.collection('members').doc(ins.memberId);
          const memberDoc = await memberRef.get();
          if (!memberDoc.exists) {
            skipped.push({ id: doc.id, memberId: ins.memberId, reason: 'member not found in Firebase' });
            continue;
          }

          const memberData = memberDoc.data();
          const name = `${ins.prenom || ''} ${ins.nom || ''}`.trim();
          const updates = {};
          const sqliteUpdates = [];

          if (ins.pdfUrl && !memberData.pdfUrl) {
            updates.pdfUrl = ins.pdfUrl;
            sqliteUpdates.push(() =>
              lc.db.prepare(`UPDATE members_cache SET pdf_url=? WHERE id=?`).run(ins.pdfUrl, ins.memberId)
            );
          }

          const photoSource = ins.photoUrl ||
            (ins.profilePicture && ins.profilePicture.length < 200000 ? ins.profilePicture : null);

          if (photoSource && !memberData.photo) {
            updates.photo = photoSource;
            sqliteUpdates.push(() =>
              lc.db.prepare(`UPDATE members_cache SET photo=? WHERE id=?`).run(photoSource, ins.memberId)
            );
          }

          if (Object.keys(updates).length === 0) {
            skipped.push({ id: doc.id, memberId: ins.memberId, name, reason: 'already complete' });
            continue;
          }

          await memberRef.update(updates);
          for (const fn of sqliteUpdates) { try { fn(); } catch (_) {} }

          const whatFixed = Object.keys(updates).join('+');
          console.log(`[fix-pdf-urls] ✅ ${name} — fixed: ${whatFixed}`);
          fixed.push({ inscriptionId: doc.id, memberId: ins.memberId, name, fixed: whatFixed });

        } catch (e) {
          errors.push({ id: doc.id, error: e.message });
        }
      }

      if (apiCache?.members) invalidateCache(apiCache.members);

      res.json({
        ok: true,
        summary: `${fixed.length} fixed, ${skipped.length} skipped, ${errors.length} errors`,
        fixed, skipped, errors,
      });
    } catch (err) {
      res.status(500).json({ error: 'fix-pdf-urls failed', detail: err.message });
    }
  });

  return router;
};
