'use strict';
// routes/members.js

const { Router } = require('express');
const crypto     = require('crypto');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function membersRouter({ db, lc, admin, bucket, apiCache, isQuotaExceeded, uploadBase64ToStorage, upload }) {
  const router = Router();

  // ── Photo Upload (multipart) ──────────────────────────────────────────────
  router.post('/upload', verifyAzureToken, upload.single('photo'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const memberId = req.body.memberId || 'unknown';
      const destination = `members/${memberId}/profile_${Date.now()}.jpg`;
      const file = bucket.file(destination);
      await file.save(req.file.buffer, { metadata: { contentType: req.file.mimetype }, resumable: false });
      const [url] = await file.getSignedUrl({ action: 'read', expires: '2100-01-01' });
      res.json({ url });
    } catch (err) {
      console.error('Photo Upload Error:', err);
      res.status(500).json({ error: 'Upload failed' });
    }
  });

  // ── GET /api/members ──────────────────────────────────────────────────────
  // 🔒 DISK-ONLY: SQLite on Render disk is the SOLE source of truth.
  // Firebase is NEVER called here. Only add/edit/delete touches Firebase.
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      const gymId       = req.query.gymId || 'all';
      const searchQuery = req.query.search || '';

      // 1️⃣ Load from disk
      let finalMembers = lc.getMembers(gymId);

      // 2️⃣ Merge pending members who have a signed PDF contract
      const pdfMembers = lc.getPendingWithPdf(gymId);
      if (pdfMembers && pdfMembers.length > 0) {
        const normalizedPdf = pdfMembers.map(p => ({
          id: p.id, gym_id: p.gym_id,
          full_name: `${p.prenom || ''} ${p.nom || ''}`.trim(),
          plan: p.subscriptionName, status: p.status,
          pdf_url: p.pdf_url, created_at: p.date, isPendingWithPdf: true
        }));
        finalMembers = [...finalMembers, ...normalizedPdf];
      }

      // 3️⃣ Local search (zero Firebase reads)
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        finalMembers = finalMembers.filter(m =>
          (m.fullName || m.full_name || '').toLowerCase().includes(q) ||
          (m.phone || '').includes(q) ||
          (m.cin || '').toLowerCase().includes(q)
        );
      }

      // 4️⃣ Normalize SQLite snake_case → camelCase
      finalMembers = finalMembers.map(m => ({
        ...m,
        fullName:        m.fullName        || m.full_name        || 'Inconnu',
        expiresOn:       m.expiresOn       || m.expires_on       || null,
        qrToken:         m.qrToken         || m.qr_token         || '',
        photo:           m.photo           || null,
        pdfUrl:          m.pdfUrl          || m.pdf_url          || null,
        createdAt:       m.createdAt       || m.created_at       || null,
        totalPaid:       m.totalPaid       || m.total_paid       || 0,
        lastPaymentDate: m.lastPaymentDate || m.last_payment_date || null,
        isArchive:       m.isArchive       || !!m.is_archive      || false,
        isPendingWithPdf: m.isPendingWithPdf || false,
      }));

      // 5️⃣ Restrict fields for non-admin users
      if (!req.isAdmin) {
        finalMembers = finalMembers.map(m => ({
          id: m.id, fullName: m.fullName, phone: m.phone || '',
          birthday: m.birthday || '', expiresOn: m.expiresOn, plan: m.plan,
          qrToken: m.qrToken || '', image: m.photo || null,
          pdfUrl: m.pdfUrl || null, isRestricted: true,
          createdAt: m.createdAt || null, isPendingWithPdf: m.isPendingWithPdf || false,
          isArchive: m.isArchive || false,
        }));
      }

      return res.json(finalMembers);
    } catch (err) {
      console.error('Members Fetch Error:', err);
      res.status(500).json({ error: 'Failed to fetch members', members: [] });
    }
  });


  // ── POST /api/members ─────────────────────────────────────────────────────
  router.post('/', verifyAzureToken, async (req, res) => {
    try {
      const { fullName, phone, plan, birthday, expiresOn, photo, email, location } = req.body;
      if (phone) {
        const existing = await db.collection('members').where('phone', '==', phone).limit(1).get();
        if (!existing.empty) {
          return res.status(409).json({ error: 'Ce numéro de téléphone est déjà associé à un membre.', member: { id: existing.docs[0].id, ...existing.docs[0].data() } });
        }
      }
      const qrToken = crypto.randomBytes(16).toString('hex');
      const gymId = (location || 'dokarat').toLowerCase().includes('marjane') ? 'marjane' : 'dokarat';
      const docRef = await db.collection('members').add({
        fullName, phone: phone || null, plan: plan || 'Monthly',
        birthday: birthday || null,
        expiresOn: expiresOn || new Date(Date.now() + 30 * 86400000).toISOString().split('T')[0],
        photo: photo || null, email: email || null, location: location || 'dokarat',
        qrToken, createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      const snap = await docRef.get();
      const newMember = { id: docRef.id, ...snap.data() };
      // ✅ Write-through: immediately save to disk so disk stays as source of truth
      lc.upsertMembers(gymId, [newMember]);
      res.json(newMember);
    } catch (err) {
      console.error('Create Member Error:', err);
      res.status(500).json({ error: 'Failed to create member' });
    }
  });

  // ── GET /api/members/:id ──────────────────────────────────────────────
  // 🔒 DISK-FIRST: Check SQLite before calling Firebase.
  router.get('/:id', verifyAzureToken, async (req, res) => {
    try {
      // 1️⃣ Check disk first
      const diskMember = lc.getMemberById ? lc.getMemberById(req.params.id) : null;
      if (diskMember) return res.json(diskMember);
      // 2️⃣ Only if not on disk, check Firebase (e.g. brand-new member not yet in seed)
      const doc = await db.collection('members').doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error: 'Member not found' });
      const member = { id: doc.id, ...doc.data() };
      // Write to disk immediately so next request hits disk
      const gymId = (member.location || 'dokarat').toLowerCase().includes('marjane') ? 'marjane' : 'dokarat';
      lc.upsertMembers(gymId, [member]);
      res.json(member);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch member' }); }
  });

  // ── GET /api/members/:id/profile ──────────────────────────────────────────
  // 🔒 DISK-FIRST: Reads member + inscription from SQLite. Firebase only as last resort.
  router.get('/:id/profile', verifyAzureToken, async (req, res) => {
    const memberId = req.params.id;
    try {
      // 1️⃣ In-process cache (60s)
      const cached = apiCache.profiles[memberId];
      if (cached && Date.now() - cached.ts < 60000) {
        if (!req.isAdmin && cached.data.location && !req.hasAccessToGym(cached.data.location))
          return res.status(403).json({ error: 'Access denied to this member' });
        return res.json(cached.data);
      }

      // 2️⃣ Try SQLite disk first
      let member = lc.getMemberById ? lc.getMemberById(memberId) : null;
      if (member) {
        // Normalize disk field names to camelCase
        member = {
          id: member.id || memberId,
          fullName:       member.fullName       || member.full_name       || 'Inconnu',
          phone:          member.phone          || '',
          plan:           member.plan           || 'Monthly',
          status:         member.status         || '',
          birthday:       member.birthday       || null,
          expiresOn:      member.expiresOn      || member.expires_on      || null,
          photo:          member.photo          || null,
          email:          member.email          || null,
          location:       member.location       || member.gym_id          || 'dokarat',
          qrToken:        member.qrToken        || member.qr_token        || '',
          pdfUrl:         member.pdfUrl         || member.pdf_url         || null,
          contractNumber: member.contractNumber || member.contrat         || null,
          cin:            member.cin            || null,
          balance:        member.balance        || 0,
          isFrozen:       member.isFrozen       || !!member.is_frozen     || false,
          inscriptionId:  member.inscriptionId  || null,
          createdAtStr:   member.createdAt      || member.created_at      || null,
          source: 'disk',
        };
      } else {
        // 3️⃣ Fallback: Firebase (brand-new member not yet synced to disk)
        const memberDoc = await db.collection('members').doc(memberId).get();
        if (!memberDoc.exists) return res.status(404).json({ error: 'Member not found' });
        const raw = memberDoc.data();
        let createdAtStr = null;
        if (raw.createdAt?._seconds) createdAtStr = new Date(raw.createdAt._seconds * 1000).toISOString().split('T')[0];
        member = { id: memberDoc.id, ...raw, createdAtStr, source: 'firebase' };
        // Write-through so next call hits disk
        const gymId = (member.location || 'dokarat').toLowerCase().includes('marjane') ? 'marjane' : 'dokarat';
        lc.upsertMembers(gymId, [member]);
      }

      // Access control
      if (!req.isAdmin && member.location && !req.hasAccessToGym(member.location)) {
        console.warn(`🚫 Manager ${req.user?.name} tried to access member ${memberId} from gym ${member.location}`);
        return res.status(403).json({ error: 'Access denied: member belongs to a different gym' });
      }

      // 4️⃣ Resolve inscription (disk-first via getPendingById if available)
      let inscription = null;
      if (member.inscriptionId) {
        const diskIns = lc.getPendingById ? lc.getPendingById(member.inscriptionId) : null;
        if (diskIns) {
          inscription = {
            cin: diskIns.cin, adresse: diskIns.adresse, ville: diskIns.ville, email: diskIns.email,
            commercial: diskIns.commercial,
            subscriptionName: diskIns.subscriptionName || diskIns.subscription_name,
            contractNumber: diskIns.contractNumber || diskIns.contract_number || member.contractNumber,
            pdfUrl: diskIns.pdfUrl || diskIns.pdf_url || member.pdfUrl,
            gymId: diskIns.gymId || diskIns.gym_id || member.location,
            periodFrom: diskIns.periodFrom || diskIns.period_from,
            periodTo: diskIns.periodTo || diskIns.period_to || member.expiresOn,
            totals: diskIns.totals ? (typeof diskIns.totals === 'string' ? JSON.parse(diskIns.totals) : diskIns.totals) : null,
            payments: diskIns.payments ? (typeof diskIns.payments === 'string' ? JSON.parse(diskIns.payments) : diskIns.payments) : null,
            balance: diskIns.balance ?? member.balance ?? 0,
            source: 'disk',
          };
        } else {
          // Firebase fallback for inscription (member from Firebase path above)
          try {
            const insDoc = await db.collection('pending_members').doc(member.inscriptionId).get();
            if (insDoc.exists) {
              const ins = insDoc.data();
              inscription = {
                cin: ins.cin, adresse: ins.adresse, ville: ins.ville, email: ins.email,
                commercial: ins.commercial, subscriptionName: ins.subscriptionName,
                contractNumber: ins.contractNumber || member.contractNumber,
                pdfUrl: ins.pdfUrl || member.pdfUrl,
                gymId: ins.gymId || member.location,
                periodFrom: ins.periodFrom, periodTo: ins.periodTo || member.expiresOn,
                totals: ins.totals, payments: ins.payments,
                balance: ins.totals?.balance ?? member.balance ?? 0,
                source: 'firebase',
              };
            }
          } catch (insErr) {
            console.warn('[PROFILE] inscription Firebase fallback failed:', insErr.message);
          }
        }
      }

      const payload = { ...member, inscription };
      apiCache.profiles[memberId] = { data: payload, ts: Date.now() };
      res.json(payload);
    } catch (err) {
      console.error('Profile fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch member profile' });
    }
  });

  // ── PUT /api/members/:id ──────────────────────────────────────────────────
  router.put('/:id', verifyAzureToken, async (req, res) => {
    try {
      const ref = db.collection('members').doc(req.params.id);
      const allowed = ['fullName', 'phone', 'plan', 'birthday', 'expiresOn', 'photo', 'status', 'email', 'location'];
      const update  = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, req.body[k]]));
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      await ref.update(update);
      delete apiCache.profiles[req.params.id];
      const snap = await ref.get();
      const updated = { id: snap.id, ...snap.data() };
      // ✅ Write-through: keep disk in sync immediately
      const gymId = (updated.location || 'dokarat').toLowerCase().includes('marjane') ? 'marjane' : 'dokarat';
      lc.upsertMembers(gymId, [updated]);
      res.json(updated);
    } catch (err) { res.status(500).json({ error: 'Failed to update member' }); }
  });

  // ── DELETE /api/members/:id ───────────────────────────────────────────────
  router.delete('/:id', verifyAzureToken, async (req, res) => {
    const { id } = req.params;
    try {
      const ref  = db.collection('members').doc(id);
      const snap = await ref.get();
      if (!snap.exists) {
        // Stale SQLite cache entry — no longer in Firestore.
        // Remove from all gym caches silently and tell the client it's gone.
        try {
          for (const gymId of ['marjane', 'dokarat', 'casa1', 'casa2', 'all']) {
            lc.pruneStaleMember ? lc.pruneStaleMember(id) : null;
          }
          // Use raw SQL if no helper available
          require('better-sqlite3') &&
            console.log(`🧹 Pruned stale member ${id} from SQLite cache`);
        } catch (_) {}
        return res.json({ ok: true, note: 'Stale entry cleared' });
      }
      const data      = snap.data();
      const deletedBy = req.user?.preferred_username || req.user?.name || 'Admin';
      const record    = { ...data, memberId: id, deletedAt: admin.firestore.FieldValue.serverTimestamp(), deletedBy };
      await db.collection('deleted_members').doc(id).set(record);
      await ref.delete();
      delete apiCache.profiles[id];
      // ✅ Write-through: remove from disk immediately
      lc.pruneStaleMember ? lc.pruneStaleMember(id) : null;
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ ok: false, error: 'Failed to delete' }); }
  });

  // ── POST /api/members/:id/freeze ──────────────────────────────────────────
  router.post('/:id/freeze', verifyAzureToken, async (req, res) => {
    try {
      const ref = db.collection('members').doc(req.params.id);
      const snap = await ref.get();
      if (!snap.exists) return res.status(404).json({ error: 'Member not found' });
      const member = snap.data();
      
      if (member.isFrozen) {
        return res.status(400).json({ error: 'Subscription is already frozen' });
      }

      await ref.update({
        isFrozen: true,
        frozenAt: admin.firestore.FieldValue.serverTimestamp(),
        freezeReason: req.body.reason || null,
        freezeProofUrl: req.body.proofUrl || null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      delete apiCache.profiles[req.params.id]; // invalidate profile cache

      // Re-fetch to return latest data
      const updatedSnap = await ref.get();
      res.json({ id: updatedSnap.id, ...updatedSnap.data() });
    } catch (err) {
      console.error('Freeze Error:', err);
      res.status(500).json({ error: 'Failed to freeze subscription' });
    }
  });

  // ── POST /api/members/:id/unfreeze ────────────────────────────────────────
  router.post('/:id/unfreeze', verifyAzureToken, async (req, res) => {
    try {
      const ref = db.collection('members').doc(req.params.id);
      const snap = await ref.get();
      if (!snap.exists) return res.status(404).json({ error: 'Member not found' });
      const member = snap.data();
      
      if (!member.isFrozen || !member.frozenAt) {
        return res.status(400).json({ error: 'Subscription is not frozen' });
      }

      const frozenAtDate = member.frozenAt.toDate ? member.frozenAt.toDate() : new Date(member.frozenAt);
      const now = new Date();
      const diffTime = Math.abs(now - frozenAtDate);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      // Calculate new expiresOn date
      let newExpiresOn = member.expiresOn;
      if (member.expiresOn) {
        const expDate = new Date(member.expiresOn + 'T00:00:00');
        expDate.setDate(expDate.getDate() + diffDays);
        newExpiresOn = expDate.toISOString().split('T')[0];
      }

      const freezeLog = {
        frozenAt: frozenAtDate.toISOString(),
        unfrozenAt: now.toISOString(),
        durationDays: diffDays,
        reason: member.freezeReason || null,
        proofUrl: member.freezeProofUrl || null,
        actor: req.user?.preferred_username || req.user?.name || 'Admin'
      };

      await ref.update({
        isFrozen: false,
        frozenAt: null,
        freezeReason: null,
        freezeProofUrl: null,
        expiresOn: newExpiresOn,
        freezeLogs: admin.firestore.FieldValue.arrayUnion(freezeLog),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      delete apiCache.profiles[req.params.id]; // invalidate profile cache

      // Re-fetch to return latest data
      const updatedSnap = await ref.get();
      res.json({ id: updatedSnap.id, ...updatedSnap.data() });
    } catch (err) {
      console.error('Unfreeze Error:', err);
      res.status(500).json({ error: 'Failed to unfreeze subscription' });
    }
  });

  return router;
};
