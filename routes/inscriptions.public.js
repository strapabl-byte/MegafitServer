'use strict';
// routes/inscriptions.public.js
// Public tablet-facing routes — form submission & member search require NO auth
// Financial routes:
//   /public/debtors        → dual auth: X-Inject-Secret OR Azure Bearer token
//   /public/settle-balance → dual auth: X-Inject-Secret OR Azure Bearer token
//   (QR-code commercial staff have no Azure account — inject secret covers them)

const { Router } = require('express');
const { verifyAzureToken } = require('../middleware/auth');
const sharp = require('sharp');

async function compressBase64Image(base64Str, type = 'profile') {
  if (!base64Str || typeof base64Str !== 'string') return base64Str;
  if (!base64Str.startsWith('data:image')) return base64Str;
  
  try {
    const matches = base64Str.match(/^data:image\/(\w+);base64,(.+)$/);
    if (!matches) return base64Str;
    
    const ext = matches[1];
    const data = matches[2];
    const buffer = Buffer.from(data, 'base64');
    
    let processed;
    if (type === 'profile') {
      processed = await sharp(buffer)
        .resize(150, 150, { fit: 'cover' })
        .jpeg({ quality: 80 })
        .toBuffer();
    } else {
      processed = await sharp(buffer)
        .resize(800, null, { withoutEnlargement: true })
        .jpeg({ quality: 60 })
        .toBuffer();
    }
    
    return `data:image/jpeg;base64,${processed.toString('base64')}`;
  } catch (err) {
    console.warn(`[IMAGE COMPRESS] Warning: failed to compress base64 ${type} image (non-blocking):`, err.message);
    return base64Str;
  }
}

module.exports = function inscriptionsPublicRouter({ db, admin, lc, apiCache, uploadBase64ToStorage, invalidateCache }) {
  const router = Router();

  // 🔒 Dual-auth: accept X-Inject-Secret header OR a valid Azure Bearer token.
  // Used only for READ-ONLY endpoints (debtors list).
  // Write endpoints (settle-balance) must still use full verifyAzureToken.
  function requireDebtorAccess(req, res, next) {
    const injectSecret = process.env.INJECT_SECRET;
    const clientSecret = req.headers['x-inject-secret'];

    // Fast path: valid shared secret
    if (injectSecret && clientSecret && clientSecret === injectSecret) {
      req.user = { name: 'PWA-Shared-Secret', isServiceAccount: true };
      return next();
    }

    // Fallback: full Azure JWT verification
    return verifyAzureToken(req, res, next);
  }

  const GYM_ALIAS_MAP = {
    'dokarat': 'dokarat', 'dokkarat': 'dokarat', 'doukkarate': 'dokarat', 'fes dokkarat': 'dokarat', 'doukarat': 'dokarat',
    'marjane': 'marjane', 'saiss': 'marjane', 'fes saiss': 'marjane', 'marjan': 'marjane',
    'casa1':   'casa1',   'anfa': 'casa1', 'casa anfa': 'casa1', 'casablanca anfa': 'casa1',
    'casa2':   'casa2',   'lady': 'casa2', 'casa lady': 'casa2', 'casa casa lady': 'casa2', 'casa lady': 'casa2',
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

  // ── GET /public/debtors ─────────────────────── 🔒 DUAL-AUTH (secret or Azure) ──
  router.get('/public/debtors', requireDebtorAccess, async (req, res) => {
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

  // ── POST /public/settle-balance ─────────────────────────────── 🔒 DUAL-AUTH ──
  // Accepts X-Inject-Secret (PWA QR-code commercials) OR Azure Bearer token (web dashboard).
  // This covers both auth paths: staff tablets (no Azure) and dashboard admin users.
  router.post('/public/settle-balance', requireDebtorAccess, async (req, res) => {
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
          abonnement: `COMPL. ${member.subscriptionName || member.plan || ''}`.trim(),
          reste: newBalance,
          note_reste: newBalance > 0 ? `Reste: ${newBalance} DH` : 'Reste réglé ✅',
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

      // 🔧 FIX: Update the ORIGINAL register entry's reste to newBalance
      // Without this, the original entry keeps showing reste > 0 in KPI stats
      try {
        const contractNum = member.contractNumber || '';
        const memberName = member.fullName || '';
        let origRow = null;
        if (contractNum && contractNum.trim() !== '' && contractNum.trim() !== '-') {
          origRow = lc.db.prepare(
            `SELECT id, gym_id, date FROM register_cache
             WHERE contrat = ? AND COALESCE(source, '') != 'reste_settlement' AND CAST(reste AS REAL) > 0
             ORDER BY date DESC LIMIT 1`
          ).get(contractNum);
        }
        if (!origRow && memberName) {
          origRow = lc.db.prepare(
            `SELECT id, gym_id, date FROM register_cache
             WHERE nom = ? AND gym_id = ? AND COALESCE(source, '') != 'reste_settlement' AND CAST(reste AS REAL) > 0
             ORDER BY date DESC LIMIT 1`
          ).get(memberName, gymId);
        }
        if (origRow) {
          const noteUpdate = newBalance <= 0
            ? `✅ Soldé — ${payAmount} DH payé le ${today}`
            : `⚠️ Reste: ${newBalance} DH (${payAmount} DH payé le ${today})`;
          lc.db.prepare('UPDATE register_cache SET reste = ?, note_reste = ? WHERE id = ? AND gym_id = ?')
            .run(newBalance, noteUpdate, origRow.id, origRow.gym_id);
          // Also update Firestore (non-blocking)
          try {
            db.collection('megafit_daily_register').doc(`${origRow.gym_id}_${origRow.date}`)
              .collection('entries').doc(origRow.id)
              .update({ reste: newBalance, note_reste: noteUpdate }).catch(() => {});
          } catch (_) {}
          console.log(`🔧 [Settle/Public] Updated original entry ${origRow.id} reste: ${newBalance} DH`);
        }
      } catch (origErr) {
        console.warn('[Settle/Public] Original entry update failed (non-blocking):', origErr.message);
      }
      console.log(`✅ [Settle/Public] ${member.fullName} | Paid: ${payAmount} DH | New balance: ${newBalance} DH`);

      // 🔔 Notification: payment received
      try {
        lc.addNotification({
          type: 'payment',
          gymId: gymId,
          title: `💳 Paiement reçu — ${member.fullName}`,
          message: `${payAmount.toLocaleString()} DH payé (${method || 'Espèces'})${newBalance > 0 ? ` · Reste: ${newBalance} DH` : ' · Solde réglé ✅'}`,
          severity: newBalance === 0 ? 'info' : 'warning',
          route: '/payments',
          icon: '💳',
          refId: payRef.id,
        });
      } catch(_) {}

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
      let { profilePicture, memberSignature, chequePhoto, chequePhotoVerso, ...safeData } = data;

      // ⚡ Compress base64 images to save Render disk space and bandwidth
      if (profilePicture) {
        profilePicture = await compressBase64Image(profilePicture, 'profile');
      }
      if (chequePhoto) {
        chequePhoto = await compressBase64Image(chequePhoto, 'cheque');
      }
      if (chequePhotoVerso) {
        chequePhotoVerso = await compressBase64Image(chequePhotoVerso, 'cheque');
      }

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
              memberSignature: memberSignature || null,  // ✅ preserve signature for PDF regen
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

        // 🔒 Auto-lock: 0 DH / free offers require direction approval
        const totalPaid = Number(safeData.totals?.paid || 0);
        const totalDue  = Number(safeData.totals?.total || 0);
        const subName   = (safeData.subscriptionName || '').toLowerCase();
        const isOffreOrFree = totalDue === 0 || (totalPaid === 0 && totalDue === 0) || subName.includes('offre') || subName.includes('gratuit') || subName.includes('offer');
        const autoStatus = isOffreOrFree ? 'locked' : 'pending';

        // safeData already stripped at top of handler (profilePicture, memberSignature etc. removed)
        t.set(newDocRef, {
          ...safeData,
          contractNumber: finalNum,
          gymId: normalizedGymId,
          source: 'web',
          status: autoStatus,
          lockedBy: isOffreOrFree ? 'AUTO — Offre/0 DH' : null,
          lockedAt: isOffreOrFree ? admin.firestore.FieldValue.serverTimestamp() : null,
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
        memberSignature: memberSignature || null,  // ✅ preserve signature for dashboard PDF regen
        createdAt: { _seconds: Math.floor(Date.now() / 1000) }
      });

      invalidateCache(apiCache.inscriptions);
      console.log(`[Inscription] ✅ Success for ${data.prenom} ${data.nom}`);

      // 🔔 Notification: new inscription
      try {
        const totalPaid = Number(safeData.totals?.paid || 0);
        lc.addNotification({
          type: 'inscription',
          gymId: normalizedGymId,
          title: `📋 Nouvelle inscription — ${data.prenom} ${data.nom}`,
          message: `${safeData.subscriptionName || 'Abonnement'} · ${totalPaid > 0 ? totalPaid + ' DH payé' : '0 DH'} · Contrat #${finalContractNumber}`,
          severity: totalPaid === 0 ? 'warning' : 'info',
          route: '/members',
          icon: '📋',
          refId: id,
        });
      } catch(_) {}

      res.json({ id, ok: true, contractNumber: finalContractNumber });

      // ── 🤖 NON-BLOCKING AI Smart Assessment ───────────────────────────────
      // Runs AFTER the response is sent — never slows down the PWA.
      // Loads official prices from config, validates payment/phone/email/CIN.
      // Stores result in aiAssessment field so dashboard never re-checks.
      (async () => {
        try {
          const GROQ_KEY = process.env.GROQ_API_KEY;
          if (!GROQ_KEY) return;

          // 1. Load official subscription prices for this gym
          let officialPrices = '';
          try {
            const cfgDoc = await db.collection('config').doc(`inscription-${normalizedGymId}`).get();
            if (cfgDoc.exists) {
              const groups = cfgDoc.data().subscriptionGroups || [];
              const priceLines = [];
              groups.forEach(g => {
                (g.options || []).forEach(o => {
                  if (o.name && o.price > 0) priceLines.push(`  ${o.name}: ${o.price} DH`);
                });
              });
              if (priceLines.length > 0) officialPrices = `\nOfficial subscription prices for this gym:\n${priceLines.join('\n')}`;
            }
          } catch (_) {}

          // 2. Build comprehensive validation prompt
          const subName = safeData.subscriptionName || 'N/A';
          const totalDue = Number(safeData.totals?.total || 0);
          const totalPaid = Number(safeData.totals?.paid || 0);
          const balance = Number(safeData.totals?.balance || 0);
          const subPrice = Number(safeData.totals?.subscription || 0);
          const phone = safeData.telephone || '';
          const email = safeData.email || '';
          const cin = safeData.cin || '';
          const nom = safeData.nom || '';
          const prenom = safeData.prenom || '';
          const dateNaissance = safeData.dateNaissance || '';
          const periodFrom = safeData.periodFrom || '';
          const periodTo = safeData.periodTo || '';

          const prompt = `Tu es une IA de contrôle qualité pour les inscriptions en salle de sport MEGA FIT au Maroc.
Analyse cette inscription et donne un verdict STRICT en JSON:
${officialPrices}

Inscription soumise:
- Membre: ${prenom} ${nom}
- Abonnement: ${subName}
- Prix abonnement: ${subPrice} DH
- Total dû: ${totalDue} DH
- Montant payé: ${totalPaid} DH
- Reste: ${balance} DH
- Téléphone: "${phone}"
- Email: "${email}"
- CIN: "${cin}"
- Date naissance: "${dateNaissance}"
- Période: ${periodFrom} → ${periodTo}

Vérifie TOUT:
1. PAIEMENT: Le prix payé est-il cohérent avec le prix officiel de cet abonnement? Un paiement partiel (50%+) est acceptable. Moins de 40% du prix = suspect.
2. TELEPHONE: Format marocain valide? (06/07/05 + 8 chiffres = 10 chiffres total)
3. EMAIL: Présent ou manquant? Format valide?
4. CIN: Format marocain? (1-2 lettres + 5-7 chiffres, ex: AB123456)
5. CHAMPS MANQUANTS: Nom, prénom, date naissance, période?
6. PRIX vs OFFICIEL: Si le prix officiel existe dans la liste, le montant correspond-il?

Réponds UNIQUEMENT en JSON valide (pas de markdown):
{"status":"ok|warning|error","message":"Résumé court en 1 phrase","issues":[]}
- status "ok": tout est bon
- status "warning": problème mineur (email manquant, petit écart de prix)
- status "error": problème grave (gros écart de prix, téléphone invalide, données manquantes critiques)
- issues: liste des problèmes détectés (strings courts)
- message: résumé humain en français, max 20 mots`;

          const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { Authorization: `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              model: 'llama-3.3-70b-versatile',
              messages: [{ role: 'user', content: prompt }],
              temperature: 0.1,
              max_tokens: 200,
            }),
          });

          if (!groqRes.ok) throw new Error(`Groq HTTP ${groqRes.status}`);
          const groqData = await groqRes.json();
          const rawText = groqData.choices?.[0]?.message?.content || '';
          const jsonMatch = rawText.match(/\{[\s\S]*\}/);

          let assessment = { status: 'ok', message: 'Analyse IA indisponible', issues: [] };
          if (jsonMatch) {
            try { assessment = JSON.parse(jsonMatch[0]); } catch (_) {}
          }

          // 3. Store on the inscription document (non-blocking)
          await db.collection('pending_members').doc(id).update({
            aiAssessment: {
              ...assessment,
              checkedAt: new Date().toISOString(),
              model: 'llama-3.3-70b',
            },
          });
          console.log(`[AI] ✅ Assessment for ${prenom} ${nom}: ${assessment.status} — ${assessment.message}`);

          // 🔔 Notification: AI flagged an issue
          if (assessment.status === 'warning' || assessment.status === 'error') {
            try {
              lc.addNotification({
                type: 'ai_alert',
                gymId: normalizedGymId,
                title: assessment.status === 'error'
                  ? `🔴 IA Alerte — ${prenom} ${nom}`
                  : `⚠️ IA Attention — ${prenom} ${nom}`,
                message: assessment.message + (assessment.issues?.length ? ` (${assessment.issues.join(', ')})` : ''),
                severity: assessment.status === 'error' ? 'critical' : 'warning',
                route: '/members',
                icon: assessment.status === 'error' ? '🔴' : '⚠️',
                refId: `ai_${id}`,
              });
            } catch(_) {}
          }
        } catch (aiErr) {
          console.warn(`[AI] ⚠️ Assessment failed (non-blocking):`, aiErr.message);
        }
      })();
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
  // Supports allGyms=true for Multiclub search (searches across all gyms)
  router.get('/public/members/search', async (req, res) => {
    try {
      const q = (req.query.q || '').trim().toLowerCase();
      if (q.length < 2) return res.json([]);
      const allGyms = req.query.allGyms === 'true';

      const searchTerm = `%${q}%`;
      const rows = lc.db.prepare(`
        SELECT id, full_name, phone, cin, birthday, gym_id, photo, expires_on, bonus_3months,
               email, adresse, ville, COALESCE(multiclub, 0) as multiclub
        FROM members_cache
        WHERE (LOWER(full_name) LIKE ? OR LOWER(cin) LIKE ? OR phone LIKE ?)
          AND (status IS NULL OR status = ''
               OR (LOWER(status) NOT LIKE '%delet%'
               AND LOWER(status) NOT LIKE '%supprim%'))
        LIMIT ${allGyms ? 10 : 5}
      `).all(searchTerm, searchTerm, searchTerm);

      const GYM_NAMES = { dokarat: 'F\u00e8s Doukkarate', marjane: 'F\u00e8s Sa\u00efss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };

      res.json(rows.map(m => ({
        id: m.id,
        fullName: m.full_name,
        nom:    (m.full_name || '').split(' ').slice(1).join(' ') || '',
        prenom: (m.full_name || '').split(' ')[0] || '',
        cin:     m.cin     || '',
        phone:   m.phone   || '',
        birthday: m.birthday || '',
        gymId:   m.gym_id  || '',
        gymName: GYM_NAMES[m.gym_id] || m.gym_id || '',
        photo:   m.photo   || '',
        expiresOn: m.expires_on || null,
        bonus3Months: m.bonus_3months === 1,
        multiclub: m.multiclub === 1,
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

  // ── POST /public/multiclub ───────────────────────────────────────────────
  // Enable Multiclub access for an existing member. No auth required (QR commercial).
  router.post('/public/multiclub', async (req, res) => {
    try {
      const {
        memberId, gymId: rawGymId,
        amount, method, paymentsSplit,
        chequePhoto, chequePhotoBack,
        checkNumber, bank,
        memberSignature, commercialSignature,
        commercialName, note
      } = req.body;

      const gymId = (rawGymId || '').toLowerCase().trim();
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Invalid gymId' });
      if (!memberId) return res.status(400).json({ error: 'memberId required' });
      if (!amount || Number(amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });

      const memberRef = db.collection('members').doc(memberId);
      const memberSnap = await memberRef.get();
      if (!memberSnap.exists) return res.status(404).json({ error: 'Member not found' });
      const member = memberSnap.data();

      const payAmount = Number(amount);
      const today = new Date().toISOString().slice(0, 10);
      const split = paymentsSplit || {};
      const esp = Number(split.espece || 0);
      const tpe = Number(split.carte  || split.tpe || 0);
      const vir = Number(split.virement || 0);
      const chq = Number(split.cheque  || 0);

      // Upload images (non-blocking on error)
      let chequeUrl = null, chequeUrlBack = null, sigClientUrl = null, sigCommUrl = null;
      if (chequePhoto)         chequeUrl     = await uploadBase64ToStorage(chequePhoto,         `multiclub/${memberId}/${Date.now()}_cheque_recto.jpg`);
      if (chequePhotoBack)     chequeUrlBack = await uploadBase64ToStorage(chequePhotoBack,     `multiclub/${memberId}/${Date.now()}_cheque_verso.jpg`);
      if (memberSignature)     sigClientUrl  = await uploadBase64ToStorage(memberSignature,     `multiclub/${memberId}/${Date.now()}_sig_client.png`);
      if (commercialSignature) sigCommUrl    = await uploadBase64ToStorage(commercialSignature, `multiclub/${memberId}/${Date.now()}_sig_comm.png`);

      // 1. 🔥 Mark member as multiclub in Firestore
      await memberRef.update({
        multiclub: true,
        multiclubActivatedAt: admin.firestore.FieldValue.serverTimestamp(),
        multiclubGymId: gymId,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // 2. 🔥 Payment record
      const payRef = await db.collection('payments').add({
        memberId, gymId,
        amount: payAmount,
        method: method || 'Esp\u00e8ces',
        paymentsSplit: { espece: esp, carte: tpe, virement: vir, cheque: chq },
        checkNumber: checkNumber || null,
        bank: bank || null,
        chequePhoto: chequeUrl, chequePhotoBack: chequeUrlBack,
        signatureClient: sigClientUrl, signatureCommercial: sigCommUrl,
        commercialName: (commercialName || 'COMMERCIAL').toUpperCase(),
        type: 'multiclub',
        date: new Date().toISOString(),
        note: note || `Activation Multiclub \u2014 ${member.fullName}`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        source: 'inscription_form',
      });

      // 3. 📒 Daily Register entry
      try {
        const docId = `${gymId}_${today}`;
        const addedDoc = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
          nom: member.fullName || '', tel: member.phone || '',
          contrat: member.contractNumber || '',
          commercial: (commercialName || 'COMMERCIAL').toUpperCase(),
          cin: member.cin || '',
          prix: payAmount, espece: esp, tpe, virement: vir, cheque: chq,
          abonnement: 'MULTICLUB',
          reste: 0, note_reste: '',
          source: 'multiclub',
          chequePhoto: chequeUrl, chequePhotoBack: chequeUrlBack,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        await db.collection('megafit_daily_register').doc(docId).set(
          { gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
          { merge: true }
        );
        const newSnap = await addedDoc.get();
        lc.upsertRegister(gymId, today, [{ id: addedDoc.id, ...newSnap.data() }]);
      } catch (regErr) {
        console.warn('[Multiclub] Register update failed (non-blocking):', regErr.message);
      }

      // 4. 💾 SQLite: Update member multiclub flag
      try { lc.db.prepare(`UPDATE members_cache SET multiclub=1 WHERE id=?`).run(memberId); } catch (_) {}

      console.log(`\u2705 [Multiclub] ${member.fullName} \u2014 ${payAmount} DH \u2014 Payment: ${payRef.id}`);
      res.json({ ok: true, memberId, paymentId: payRef.id, multiclub: true });

    } catch (err) {
      console.error('[Multiclub] Error:', err);
      res.status(500).json({ error: 'Failed to activate multiclub', detail: err.message });
    }
  });

  // ── POST /public/decaissement ─────────────────────────────────────────────
  // Tablet-facing: Manager scans QR → submits a décaissement request.
  // Token validated against Firestore `managerTokens` collection.
  // Photo proof is REQUIRED for non-salary types.
  // All décaissements created as 'pending' → Direction approves in Auralix.
  router.post('/public/decaissement', async (req, res) => {
    try {
      const {
        managerToken, gymId: rawGymId,
        montant, raison, categorie, beneficiaire, moyenPaiement,
        proofPhoto, managerSignature, managerName: clientManagerName
      } = req.body;

      // ── 1. Validate inputs ────────────────────────────────────────────────
      const gymId = (rawGymId || '').toLowerCase().trim();
      if (!VALID_GYMS.includes(gymId)) {
        return res.status(400).json({ error: 'Identifiant de salle invalide', received: rawGymId });
      }
      if (!managerToken) return res.status(401).json({ error: 'Token manager requis' });
      if (!montant || Number(montant) <= 0) return res.status(400).json({ error: 'Montant invalide' });
      if (!raison || !raison.trim()) return res.status(400).json({ error: 'Raison requise' });
      if (!categorie) return res.status(400).json({ error: 'Catégorie requise' });
      if (!beneficiaire || !beneficiaire.trim()) return res.status(400).json({ error: 'Bénéficiaire requis' });

      // Photo proof required for non-salary types
      const SALARY_TYPES = ['salaire'];
      const requiresProof = !SALARY_TYPES.includes((categorie || '').toLowerCase());
      if (requiresProof && !proofPhoto) {
        return res.status(400).json({ error: 'Photo justificative requise pour ce type de décaissement' });
      }

      // ── 2. Validate manager token against Door Firestore (megadoor-b3ccb) ──
      const DOOR_PROJECT = 'megadoor-b3ccb';
      const tokenUrl = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents/managerTokens/${managerToken}`;
      const tokenResp = await fetch(tokenUrl);
      if (!tokenResp.ok) {
        console.warn(`[Décaissement] ❌ Invalid manager token: ${managerToken}`);
        return res.status(401).json({ error: 'Token manager invalide ou expiré' });
      }
      const tokenJson = await tokenResp.json();
      if (!tokenJson.fields) {
        return res.status(401).json({ error: 'Token manager invalide' });
      }

      const tokenFields = tokenJson.fields;
      if (tokenFields.isActive?.booleanValue === false) {
        return res.status(401).json({ error: 'Token manager révoqué' });
      }
      if (tokenFields.expiresAt?.timestampValue) {
        const expiryDate = new Date(tokenFields.expiresAt.timestampValue);
        if (expiryDate < new Date()) {
          return res.status(401).json({ error: 'Token manager expiré' });
        }
      }
      const tokenGymId = tokenFields.gymId?.stringValue;
      if (tokenGymId && tokenGymId !== gymId) {
        return res.status(403).json({ error: 'Ce token n\'est pas autorisé pour cette salle' });
      }

      const verifiedManagerName = tokenFields.managerName?.stringValue || clientManagerName || 'Manager';

      // Update lastUsedAt on the token (best effort, non-blocking)
      try {
        await db.collection('managerTokens').doc(managerToken).update({
          lastUsedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } catch (_) {}

      // ── 3. Upload proof photo & signature to Storage ──────────────────────
      const ts = Date.now();
      let proofUrl = null, signatureUrl = null;
      if (proofPhoto) {
        proofUrl = await uploadBase64ToStorage(
          proofPhoto, `decaissements/${gymId}/${ts}_proof.jpg`
        );
      }
      if (managerSignature) {
        signatureUrl = await uploadBase64ToStorage(
          managerSignature, `decaissements/${gymId}/${ts}_signature.png`
        );
      }

      // ── 4. Create décaissement in Firestore + SQLite ──────────────────────
      const today = new Date().toISOString().slice(0, 10);
      const docId = `${gymId}_${today}`;
      const payload = {
        montant: Number(montant),
        raison: raison.trim(),
        categorie: categorie,
        beneficiaire: beneficiaire.trim(),
        proofPhoto: proofUrl,
        signature: signatureUrl,
        location: gymId,
        status: 'pending',
        source: 'tablet_qr',
        moyenPaiement: moyenPaiement || null,
        requestedBy: verifiedManagerName,
        managerTokenId: managerToken,
        approvedBy: null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: verifiedManagerName,
      };

      const ref = await db.collection('megafit_daily_register').doc(docId)
        .collection('decaissements').add(payload);
      await db.collection('megafit_daily_register').doc(docId).set(
        { gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true }
      );

      // Cache in SQLite
      const newDoc = await ref.get();
      lc.upsertDecaissements(gymId, today, [{ id: ref.id, ...newDoc.data() }]);

      console.log(`✅ [Décaissement/Tablet] ${verifiedManagerName} | ${Number(montant)} DH | ${categorie} | ${raison.trim()} | ${gymId}`);

      // 🔔 Notification: new décaissement pending
      try {
         lc.addNotification({
          type: 'decaissement',
          gymId: gymId,
          title: `Decaissement en attente - ${Number(montant).toLocaleString()} DH`,
          message: `${categorie}${moyenPaiement ? ' (' + moyenPaiement + ')' : ''} - ${beneficiaire.trim()} - ${raison.trim()} - Par ${verifiedManagerName}`,
          severity: Number(montant) >= 5000 ? 'critical' : 'warning',
          route: '/registre',
          icon: categorie === 'banque' ? '🏦' : '💰',
          refId: ref.id,
        });
      } catch(_) {}

      res.json({ ok: true, id: ref.id, status: 'pending' });

    } catch (err) {
      console.error('❌ [PUBLIC DECAISSEMENT ERROR]:', err);
      res.status(500).json({ error: 'Échec de la soumission du décaissement', detail: err.message });
    }
  });

  // ── POST /public/validate-manager-token ───────────────────────────────────
  // Quick validation: tablet checks if token is valid before showing the form.
  // Reads from Door Firestore (megadoor-b3ccb) where the dashboard writes tokens.
  // Door Firestore has public read rules, so no service account needed.
  router.post('/public/validate-manager-token', async (req, res) => {
    try {
      const { token } = req.body;
      if (!token) return res.json({ valid: false });

      // Read from Door Firestore via REST API (public read)
      const DOOR_PROJECT = 'megadoor-b3ccb';
      const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents/managerTokens/${token}`;
      const resp = await fetch(url);

      if (!resp.ok) return res.json({ valid: false });

      const doc = await resp.json();
      if (!doc.fields) return res.json({ valid: false });

      const fields = doc.fields;
      const isActive = fields.isActive?.booleanValue;
      if (isActive === false) return res.json({ valid: false, reason: 'revoked' });

      // Check expiry
      if (fields.expiresAt?.timestampValue) {
        const exp = new Date(fields.expiresAt.timestampValue);
        if (exp < new Date()) return res.json({ valid: false, reason: 'expired' });
      }

      res.json({
        valid: true,
        managerName: fields.managerName?.stringValue || 'Manager',
        gymId: fields.gymId?.stringValue || null,
      });
    } catch (err) {
      console.error('[Validate Manager Token] Error:', err);
      res.json({ valid: false });
    }
  });

  // ── POST /public/incident ──────────────────────────────────────────────────
  // Commercials can report incidents directly from the tablet PWA.
  // No Azure auth — validates gymId + requires title/emergency/reporter.
  // Shows up in dashboard Report/Incidents page.
  router.post('/public/incident', async (req, res) => {
    try {
      const { gymId: rawGymId, title, cause, explanation, emergency, reporter, category } = req.body;

      const gymId = (rawGymId || '').toLowerCase().trim();
      if (!VALID_GYMS.includes(gymId)) return res.status(400).json({ error: 'Salle invalide' });
      if (!title || !title.trim()) return res.status(400).json({ error: 'Titre requis' });
      if (!reporter || !reporter.trim()) return res.status(400).json({ error: 'Nom du reporter requis' });

      const VALID_EMERGENCIES = ['Low', 'Medium', 'High'];
      const safeEmergency = VALID_EMERGENCIES.includes(emergency) ? emergency : 'Low';

      const GYM_NAMES = { dokarat: 'Dokkarat Fès', marjane: 'Fès Saiss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
      const gymName = GYM_NAMES[gymId] || gymId;
      const today = new Date().toISOString().slice(0, 10);

      // Sanitize text inputs (max length)
      const safeTitle = title.trim().slice(0, 200);
      const safeCause = (cause || '').trim().slice(0, 500);
      const safeExplanation = (explanation || '').trim().slice(0, 500);
      const safeReporter = reporter.trim().slice(0, 100);
      const safeCategory = (category || '').trim().slice(0, 100);

      // Save to Firestore
      const docRef = await db.collection('incidents').add({
        gymId, gymName, title: safeTitle, cause: safeCause,
        explanation: safeExplanation, emergency: safeEmergency,
        reporter: safeReporter, category: safeCategory,
        date: today, status: 'Pending',
        source: 'tablet_pwa',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // Cache in SQLite
      const now = new Date().toISOString();
      lc.upsertIncidents([{
        id: docRef.id, gymId, gymName, title: safeTitle, cause: safeCause,
        explanation: safeExplanation, emergency: safeEmergency,
        reporter: safeReporter, date: today, status: 'Pending', createdAt: now,
      }]);

      // 🔔 Notification
      try {
        lc.addNotification({
          type: 'incident',
          gymId,
          title: `🚨 Incident signalé — ${safeTitle}`,
          message: `${gymName} · ${safeEmergency} · Par ${safeReporter}${safeCategory ? ` · ${safeCategory}` : ''}`,
          severity: safeEmergency === 'High' ? 'critical' : safeEmergency === 'Medium' ? 'warning' : 'info',
          route: '/report',
          icon: safeEmergency === 'High' ? '🔴' : '🟡',
          refId: docRef.id,
        });
      } catch(_) {}

      console.log(`🚨 [Incident/Tablet] ${safeReporter} | ${safeTitle} | ${safeEmergency} | ${gymId}`);
      res.json({ ok: true, id: docRef.id });

    } catch (err) {
      console.error('❌ [PUBLIC INCIDENT ERROR]:', err);
      res.status(500).json({ error: 'Échec du signalement', detail: err.message });
    }
  });

  return router;
};
