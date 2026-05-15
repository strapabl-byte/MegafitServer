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

  // ── PATCH /api/members/:id/photo (Photo Repair Tool) ───────────────────────
  router.patch('/:id/photo', verifyAzureToken, async (req, res) => {
    try {
      const { photo } = req.body;
      if (!photo) return res.status(400).json({ error: 'Photo data required' });

      const memberId = req.params.id;
      const memberRef = db.collection('members').doc(memberId);
      
      // Update Firestore
      await memberRef.update({ 
        photo, 
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        photoUpdatedBy: req.user?.preferred_username || 'Admin'
      });

      // Update SQLite Cache
      try {
        const memberDoc = await memberRef.get();
        if (memberDoc.exists) {
          lc.upsertMembers(memberDoc.data().location || 'dokarat', [{ id: memberId, ...memberDoc.data() }]);
        }
      } catch (cacheErr) {
        console.warn('[photo-repair] SQLite sync failed:', cacheErr.message);
      }

      res.json({ ok: true, message: 'Photo updated successfully' });
    } catch (err) {
      console.error('Photo Repair Error:', err);
      res.status(500).json({ error: 'Failed to update photo' });
    }
  });

  // ── GET /api/members ──────────────────────────────────────────────────────
  // 🔒 DISK-ONLY: SQLite on Render disk is the SOLE source of truth.
  // Firebase is NEVER called here. Only add/edit/delete touches Firebase.
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      let gymId = req.query.gymId || 'all';

      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!req.isAdmin) {
          const assigned = req.assignedGyms?.[0];
          if (assigned && assigned !== 'all') {
              gymId = assigned;
          } else {
              // 🚨 SECURITY: If no gym is assigned and they aren't admin, return NOTHING.
              gymId = 'none';
          }
      }
      const searchQuery = req.query.search || '';

      // 1️⃣ Load from SQLite disk cache
      let finalMembers = lc.getMembers(gymId);

      // 1b️⃣ Firebase fallback — re-hydrate any gym whose SQLite cache is empty.
      // Covers ALL 4 gyms individually, including when gymId='all' (super admin).
      // Runs in parallel — fast, and only fires when a gym cache is actually empty.
      const REAL_GYM_IDS = ['dokarat', 'marjane', 'casa1', 'casa2'];
      // Determine which gyms to check based on the request
      const gymsToRehydrate = gymId === 'all'
        ? REAL_GYM_IDS.filter(g => lc.getMembers(g).length === 0)
        : REAL_GYM_IDS.includes(gymId) && finalMembers.length === 0 ? [gymId] : [];

      if (gymsToRehydrate.length > 0) {
        console.log(`[Members] SQLite empty for: [${gymsToRehydrate.join(', ')}] — Firebase fallback...`);
        try {
          await Promise.all(gymsToRehydrate.map(async (gid) => {
            try {
              const fbSnap = await db.collection('members')
                .where('location', '==', gid)
                .limit(2000)
                .get();
              if (!fbSnap.empty) {
                const fbMembers = fbSnap.docs
                  .map(d => ({ id: d.id, ...d.data() }))
                  .filter(m => m.status !== 'deleted' && !m.deleted && !m.isDeleted);
                lc.upsertMembers(gid, fbMembers);
                console.log(`[Members] ✅ Re-cached ${fbMembers.length} members for ${gid}`);
              } else {
                console.log(`[Members] ℹ️  No members found in Firebase for ${gid}`);
              }
            } catch (e) {
              console.error(`[Members] Firebase fallback failed for ${gid}:`, e.message);
            }
          }));
          // Re-read from SQLite now that all gyms are populated
          finalMembers = lc.getMembers(gymId);
        } catch (fbErr) {
          console.error('[Members] Firebase fallback error:', fbErr.message);
        }
      }

      // 2️⃣ Merge pending members who have a signed PDF contract
      const pdfMembers = lc.getPendingWithPdf(gymId);
      
      if (pdfMembers && pdfMembers.length > 0) {
        const normalizeName = (name) => (name || '').toLowerCase().replace(/\s+/g, '');
        
        // Override member plans with their official inscription subscriptionName.
        // ONLY link by explicit inscription_id — name matching is too fragile and
        // causes ghost photos / wrong payment history when names collide.
        finalMembers = finalMembers.map(m => {
          let linkedPdf = null;
          if (m.inscription_id) {
            linkedPdf = pdfMembers.find(p => p.id === m.inscription_id);
          }
          // ⚠️ NOTE: Fallback name-based auto-link REMOVED.
          // It was causing cross-member data contamination when two members share
          // a name or when test data matched a real member's name.
          
          if (linkedPdf) {
            if (linkedPdf.subscriptionName) m.plan = linkedPdf.subscriptionName;
            if (linkedPdf.contract_number) m.contractNumber = linkedPdf.contract_number;
          }
          return m;
        });

        // Collect ALL linked inscription IDs (including the ones we just auto-linked by name)
        const allLinkedIds = new Set(finalMembers.map(m => m.inscription_id).filter(Boolean));

        // Only add pdfMembers that are NOT already linked to an existing member
        const unlinkedPdfMembers = pdfMembers.filter(p => !allLinkedIds.has(p.id));
        
        const normalizedPdf = unlinkedPdfMembers.map(p => {
          // Parse totals JSON if needed
          const totals = p.totals ? (typeof p.totals === 'string' ? JSON.parse(p.totals) : p.totals) : null;
          return {
            id: p.id,
            gym_id: p.gym_id,
            full_name: `${p.prenom || ''} ${p.nom || ''}`.trim(),
            plan: p.subscriptionName || '',
            subscription_name: p.subscriptionName || '',
            status: p.status || 'pending',
            pdf_url: p.pdf_url || null,
            pdfUrl: p.pdf_url || null,
            created_at: p.date || null,
            createdAt: p.date || null,
            phone: p.telephone || null,
            birthday: p.date_naissance || null,
            expires_on: p.period_to || null,
            expiresOn: p.period_to || null,
            period_from: p.period_from || null,
            photo: p.profile_picture || null,
            image: p.profile_picture || null,
            cin: p.cin || null,
            email: p.email || null,
            adresse: p.adresse || null,
            ville: p.ville || null,
            contract_number: p.contract_number || null,
            contractNumber: p.contract_number || null,
            balance: totals?.balance ?? p.balance ?? 0,
            isPendingWithPdf: true,
          };
        });
        
        finalMembers = [...finalMembers, ...normalizedPdf];
      }

      // 3️⃣ Local search (zero Firebase reads)
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        finalMembers = finalMembers.filter(m => 
          (m.full_name || m.fullName || '').toLowerCase().includes(q) ||
          (m.phone || '').includes(q) ||
          (m.contract_number || m.contractNumber || '').toString().includes(q)
        );
      }
      
      // 4️️⃣ Normalize SQLite snake_case → camelCase (applies to ALL gyms)
      finalMembers = finalMembers.map(m => ({
        ...m,
        fullName:         m.fullName         || m.full_name         || 'Inconnu',
        expiresOn:        m.expiresOn        || m.expires_on        || null,
        qrToken:          m.qrToken          || m.qr_token          || '',
        photo:            m.photo            || null,
        image:            m.photo            || null, // ✅ Alias for frontend consistency
        pdfUrl:           m.pdfUrl           || m.pdf_url           || null,
        createdAt:        m.createdAt        || m.created_at        || null,
        totalPaid:        m.totalPaid        || m.total_paid        || 0,
        lastPaymentDate:  m.lastPaymentDate  || m.last_payment_date || null,
        isArchive:        m.isArchive        || !!m.is_archive      || false,
        isPendingWithPdf: m.isPendingWithPdf || false,
        // ✅ Subscription name — use real form value, not generic plan code
        subscriptionName: m.subscriptionName || m.subscription_name || m.plan || '',
        // ✅ These were missing for non-Dokkarat gyms — now normalized for ALL gyms
        contractNumber:   m.contractNumber   || m.contract_number   || null,
        inscriptionId:    m.inscriptionId    || m.inscription_id    || null,
        periodFrom:       m.periodFrom       || m.period_from       || null,
        periodTo:         m.periodTo         || m.period_to         || m.expiresOn || m.expires_on || null,
        cin:              m.cin              || null,
        email:            m.email            || null,
        adresse:          m.adresse          || null,
        ville:            m.ville            || null,
        commercial:       m.commercial       || null,
      }));

      // 5️⃣ Restrict fields for non-admin users
      if (!req.isAdmin) {
        finalMembers = finalMembers.map(m => ({
          id: m.id, fullName: m.fullName, phone: m.phone || '',
          birthday: m.birthday || '', expiresOn: m.expiresOn, plan: m.plan,
          subscriptionName: m.subscriptionName || '',
          contractNumber: m.contractNumber || null,
          inscriptionId:  m.inscriptionId  || null,
          periodFrom:     m.periodFrom     || null,
          cin:            m.cin            || null,
          commercial:     m.commercial     || null,
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
        contractNumber: req.body.contractNumber || null,
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

  router.get('/api/debug-auth', verifyAzureToken, (req, res) => {
    res.json({
      user: req.user?.preferred_username || req.user?.email || 'unknown',
      isAdmin: req.isAdmin,
      isManager: req.isManager,
      assignedGyms: req.assignedGyms,
      envAdminEmails: process.env.ADMIN_EMAILS
    });
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
          fullName:        member.fullName        || member.full_name        || 'Inconnu',
          phone:           member.phone           || '',
          plan:            member.plan            || 'Monthly',
          status:          member.status          || '',
          birthday:        member.birthday        || null,
          expiresOn:       member.expiresOn       || member.expires_on       || null,
          photo:           member.photo           || null,
          email:           member.email           || null,
          location:        member.location        || member.gym_id           || 'dokarat',
          qrToken:         member.qrToken         || member.qr_token         || '',
          pdfUrl:          member.pdfUrl          || member.pdf_url          || null,
          contractNumber:  member.contractNumber  || member.contract_number  || null,
          cin:             member.cin             || null,
          balance:         member.balance         || 0,
          isFrozen:        member.isFrozen        || !!member.is_frozen      || false,
          inscriptionId:   member.inscriptionId   || member.inscription_id   || null,
          subscriptionName:member.subscriptionName|| member.subscription_name|| member.plan || null,
          periodFrom:      member.periodFrom      || member.period_from      || null,
          periodTo:        member.periodTo        || member.period_to        || member.expiresOn || member.expires_on || null,
          adresse:         member.adresse         || null,
          ville:           member.ville           || null,
          commercial:      member.commercial      || null,
          totalPaid:       member.totalPaid       || member.total_paid       || 0,
          payments:        member.payments        || null,
          createdAtStr:    member.createdAt       || member.created_at       || null,
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
        return res.status(403).json({ error: 'Access Denied: This member belongs to another gym' });
      }

      // 4️⃣ Resolve inscription data for the profile panel
      // Tier 1: direct inscriptionId link (stored on member)
      // Tier 2: reverse lookup by memberId in pending_members
      // Tier 3: build from member's own stored fields (always works)
      let inscription = null;

      const resolveInscription = async (insId) => {
        // Try SQLite disk first
        let diskIns = lc.getPendingById ? lc.getPendingById(insId) : null;
        if (diskIns && !diskIns.payments && !diskIns.totals) diskIns = null; // force Firebase if financial data missing

        if (diskIns) {
          return {
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
        }
        // Firebase fallback
        try {
          const insDoc = await db.collection('pending_members').doc(insId).get();
          if (insDoc.exists) {
            const ins = insDoc.data();
            // Repair cache
            lc.setPending ? lc.setPending({ id: insDoc.id, ...ins }) : null;
            // Also backfill inscriptionId on member document (so future calls skip this path)
            if (!member.inscriptionId) {
              await db.collection('members').doc(memberId).update({ inscriptionId: insId });
            }
            return {
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
        return null;
      };

      // Tier 1: direct inscriptionId
      if (member.inscriptionId) {
        inscription = await resolveInscription(member.inscriptionId);
      }

      // Tier 2: reverse lookup by memberId (for old members without inscriptionId stored)
      if (!inscription) {
        try {
          const reverseSnap = await db.collection('pending_members')
            .where('memberId', '==', memberId).limit(1).get();
          if (!reverseSnap.empty) {
            const insId = reverseSnap.docs[0].id;
            console.log(`🔍 [PROFILE] Reverse inscription found for member ${memberId} → ${insId}`);
            inscription = await resolveInscription(insId);
          }
        } catch (revErr) {
          console.warn('[PROFILE] Reverse lookup failed:', revErr.message);
        }
      }

      // Tier 3: fallback — build from member's own stored fields
      // This ensures the panel always shows full data even for legacy/manually-created members
      if (!inscription) {
        const hasMemberData = member.subscriptionName || member.contractNumber || member.commercial || member.periodFrom;
        if (hasMemberData) {
          inscription = {
            subscriptionName: member.subscriptionName || member.plan || null,
            contractNumber:   member.contractNumber || null,
            commercial:       member.commercial || null,
            periodFrom:       member.periodFrom || null,
            periodTo:         member.periodTo || member.expiresOn || null,
            cin:              member.cin || null,
            adresse:          member.adresse || null,
            ville:            member.ville || null,
            email:            member.email || null,
            pdfUrl:           member.pdfUrl || null,
            gymId:            member.location || null,
            totals:           member.payments ? { paid: member.totalPaid || 0, balance: member.balance || 0 } : null,
            payments:         member.payments || null,
            balance:          member.balance || 0,
            source:           'member_fields',
          };
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
      const allowed = ['fullName', 'phone', 'plan', 'birthday', 'expiresOn', 'photo', 'status', 'email', 'location', 'bonus3Months', 'contractNumber'];
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
        // It might be an inscription (pending member with PDF) merged into the list
        const pendingRef = db.collection('pending_members').doc(id);
        const pendingSnap = await pendingRef.get();
        if (pendingSnap.exists) {
            await pendingRef.delete();
            try {
                lc.db.prepare('DELETE FROM pending_cache WHERE id=?').run(id);
            } catch(e) {}
            return res.json({ ok: true, note: 'Pending inscription deleted' });
        }

        // Stale SQLite cache entry — no longer in Firestore.
        // Remove from all gym caches silently and tell the client it's gone.
        try {
          for (const gymId of ['marjane', 'dokarat', 'casa1', 'casa2', 'all']) {
            lc.pruneStaleMember ? lc.pruneStaleMember(id) : null;
          }
          // Also try to clear from pending_cache just in case
          lc.db.prepare('DELETE FROM pending_cache WHERE id=?').run(id);
          require('better-sqlite3') &&
            console.log(`🧹 Pruned stale member/inscription ${id} from SQLite cache`);
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
