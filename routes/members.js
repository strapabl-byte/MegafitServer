'use strict';
// routes/members.js

const { Router } = require('express');
const crypto     = require('crypto');
const sharp      = require('sharp');
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

      // 2b️⃣ Merge archived Odoo members (Deduplicated to avoid duplicates)
      try {
        const getGymIds = (gId) => {
          if (!gId || gId === 'all') return [];
          if (Array.isArray(gId)) return gId;
          return String(gId).split(',').map(s => s.trim()).filter(Boolean);
        };
        const buildInClause = (gymIds, prefix = 'gym_id') => {
          if (gymIds.length === 0) return { sql: '1=1', params: [] };
          const placeholders = gymIds.map(() => '?').join(',');
          return { sql: `${prefix} IN (${placeholders})`, params: gymIds };
        };

        const odooGymIds = getGymIds(gymId);
        const odooClause = buildInClause(odooGymIds);
        const odooRows = lc.db ? lc.db.prepare(`SELECT * FROM odoo_members_cache WHERE ${odooClause.sql} ORDER BY id DESC`).all(...odooClause.params) : [];
        
        const normName = (s) => (s || '').replace(/\s+/g, ' ').trim().toUpperCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        const existingNorms = new Set();
        finalMembers.forEach(m => {
          const norm = normName(m.full_name || m.fullName);
          if (norm) existingNorms.add(norm);
        });

        const uniqueOdooMap = new Map();
        odooRows.forEach(row => {
          const norm = row.name_norm || normName(row.full_name);
          if (!norm || existingNorms.has(norm)) return;

          if (!uniqueOdooMap.has(norm)) {
            uniqueOdooMap.set(norm, row);
          } else {
            const current = uniqueOdooMap.get(norm);
            if (current.status !== 'Active' && row.status === 'Active') {
              uniqueOdooMap.set(norm, row);
            }
          }
        });

        const odooMembers = Array.from(uniqueOdooMap.values()).map(row => ({
          id: `odoo-${row.id}`,
          gym_id: row.gym_id,
          location: row.gym_id,
          full_name: row.full_name,
          fullName: row.full_name,
          expires_on: row.expires_on,
          expiresOn: row.expires_on,
          status: row.status ? row.status.toLowerCase() : 'expired',
          is_archive: 1,
          isArchive: true,
          importedFromOdoo: true,
          isImported: true,
          phone: '',
          plan: 'Monthly',
          subscription_name: row.membership_name || 'Monthly',
          isPendingWithPdf: false,
        }));

        finalMembers = [...finalMembers, ...odooMembers];
      } catch (odooErr) {
        console.error('Failed to merge Odoo members:', odooErr.message);
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
        isFrozen:         m.isFrozen         || !!m.is_frozen       || false,
        frozenAt:         m.frozenAt         || m.frozen_at         || null,
        receiptEmailStatus: m.receiptEmailStatus || m.receipt_email_status || null,
        receiptEmailTo:     m.receiptEmailTo     || m.receipt_email_to     || null,
        receiptEmailReason: m.receiptEmailReason || m.receipt_email_reason || null,
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
          isFrozen: m.isFrozen || !!m.is_frozen || false,
          frozenAt: m.frozenAt || m.frozen_at || null,
          receiptEmailStatus: m.receiptEmailStatus || m.receipt_email_status || null,
          receiptEmailReason: m.receiptEmailReason || m.receipt_email_reason || null,
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

      // Check if it's an Odoo archived member
      if (req.params.id.startsWith('odoo-')) {
        const odooId = req.params.id.replace('odoo-', '');
        const row = lc.db ? lc.db.prepare('SELECT * FROM odoo_members_cache WHERE id = ?').get(odooId) : null;
        if (row) {
          return res.json({
            id: req.params.id,
            gym_id: row.gym_id,
            location: row.gym_id,
            fullName: row.full_name,
            full_name: row.full_name,
            status: 'expired',
            isArchive: true,
            is_archive: 1,
            expiresOn: row.expires_on,
            expires_on: row.expires_on,
            importedFromOdoo: true,
            isImported: true,
            phone: '',
            plan: 'Monthly',
            subscriptionName: 'Monthly',
            qrToken: '',
            photo: null,
            image: null,
            pdfUrl: null,
            createdAt: row.expires_on,
            created_at: row.expires_on,
          });
        }
      }

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
      if (!member && memberId.startsWith('odoo-')) {
        const odooId = memberId.replace('odoo-', '');
        const row = lc.db ? lc.db.prepare('SELECT * FROM odoo_members_cache WHERE id = ?').get(odooId) : null;
        if (row) {
          member = {
            id: memberId,
            fullName: row.full_name,
            full_name: row.full_name,
            phone: '',
            plan: 'Monthly',
            status: 'expired',
            birthday: null,
            expiresOn: row.expires_on,
            expires_on: row.expires_on,
            photo: null,
            email: null,
            location: row.gym_id,
            qrToken: '',
            pdfUrl: null,
            contractNumber: null,
            cin: null,
            balance: 0,
            isFrozen: false,
            inscriptionId: null,
            subscriptionName: 'Monthly',
            periodFrom: null,
            periodTo: row.expires_on,
            adresse: null,
            ville: null,
            commercial: null,
            totalPaid: 0,
            payments: null,
            createdAtStr: row.expires_on,
            source: 'odoo',
            isArchive: true,
            is_archive: 1,
            isImported: true,
          };
        }
      }
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
          frozenAt:        member.frozenAt        || member.frozen_at        || null,
          freezeReason:    member.freezeReason    || member.freeze_reason    || null,
          freezeProofUrl:  member.freezeProofUrl  || member.freeze_proof_url || null,
          freezeDuration:  member.freezeDuration  || member.freeze_duration  || null,
          freezeLogs:      (() => { const fl = member.freezeLogs || member.freeze_logs; if (!fl) return []; if (Array.isArray(fl)) return fl; try { return JSON.parse(fl); } catch { return []; } })(),
          receiptEmailStatus: member.receiptEmailStatus || member.receipt_email_status || null,
          receiptEmailAt:     member.receiptEmailAt     || member.receipt_email_at     || null,
          receiptEmailTo:     member.receiptEmailTo     || member.receipt_email_to     || null,
          receiptEmailReason: member.receiptEmailReason || member.receipt_email_reason || null,
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
            profilePicture: diskIns.profile_picture || diskIns.profilePicture || null,
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
              profilePicture: ins.profilePicture || ins.photoUrl || null,
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

      // Photo fallback: if the member doc has no photo (e.g. a base64 blob was
      // dropped at confirm), use the linked inscription's photo so the panel shows it.
      const photoFallback = member.photo || member.image || inscription?.profilePicture || null;
      const payload = { ...member, photo: photoFallback, image: photoFallback, inscription, pdfHistory: member.pdfHistory || [] };
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

      const durationDays = parseInt(req.body.durationDays) || 30; // default 1 month

      await ref.update({
        isFrozen: true,
        frozenAt: admin.firestore.FieldValue.serverTimestamp(),
        freezeReason: req.body.reason || null,
        freezeProofUrl: req.body.proofUrl || null,
        freezeDuration: durationDays,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      delete apiCache.profiles[req.params.id]; // invalidate profile cache

      // Re-fetch to return latest data
      const updatedSnap = await ref.get();
      const updated = updatedSnap.data();

      // 🔒 Persist to disk too — the dashboard reads disk-first, so without this the
      // freeze would vanish on refresh (writes to Firestore only were invisible on reload).
      const frozenAtIso = updated.frozenAt?.toDate ? updated.frozenAt.toDate().toISOString() : new Date().toISOString();
      try {
        lc.setMemberFreeze?.(req.params.id, {
          is_frozen: 1,
          frozen_at: frozenAtIso,
          freeze_reason: req.body.reason || null,
          freeze_proof_url: req.body.proofUrl || null,
          freeze_duration: durationDays,
        });
      } catch (diskErr) { console.warn('[Freeze] disk write failed:', diskErr.message); }

      res.json({ id: updatedSnap.id, ...updated });
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

      // Use the pre-planned freeze duration if available, otherwise fall back to time-elapsed
      let diffDays;
      if (member.freezeDuration && member.freezeDuration > 0) {
        diffDays = member.freezeDuration;
      } else {
        const frozenAtDate = member.frozenAt.toDate ? member.frozenAt.toDate() : new Date(member.frozenAt);
        const now = new Date();
        const diffTime = Math.abs(now - frozenAtDate);
        diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      }

      const frozenAtDate = member.frozenAt.toDate ? member.frozenAt.toDate() : new Date(member.frozenAt);
      const now = new Date();

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
        freezeDuration: null,
        expiresOn: newExpiresOn,
        freezeLogs: admin.firestore.FieldValue.arrayUnion(freezeLog),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      delete apiCache.profiles[req.params.id]; // invalidate profile cache

      // 🔒 Mirror to disk: clear freeze state, push out expiry, append the log — so the
      // refresh (disk-first read) shows the member un-frozen with the extended expiry.
      try {
        const diskRow = lc.getMemberById ? lc.getMemberById(req.params.id) : null;
        let logs = [];
        if (diskRow?.freeze_logs) { try { logs = JSON.parse(diskRow.freeze_logs) || []; } catch { logs = []; } }
        logs.push(freezeLog);
        lc.setMemberFreeze?.(req.params.id, {
          is_frozen: 0,
          frozen_at: null,
          freeze_reason: null,
          freeze_proof_url: null,
          freeze_duration: null,
          expires_on: newExpiresOn || null,
          freeze_logs: JSON.stringify(logs),
        });
      } catch (diskErr) { console.warn('[Unfreeze] disk write failed:', diskErr.message); }

      // Re-fetch to return latest data
      const updatedSnap = await ref.get();
      res.json({ id: updatedSnap.id, ...updatedSnap.data() });
    } catch (err) {
      console.error('Unfreeze Error:', err);
      res.status(500).json({ error: 'Failed to unfreeze subscription' });
    }
  });

  // ── POST /api/members/:id/receipt-status ──────────────────────────────────
  // Records the outcome of the auto-emailed billing receipt (Reçu de paiement).
  // 'sent' | 'no_email' | 'error' | 'pending'. Failures raise a red notification
  // and the Payments page flags the member red.
  router.post('/:id/receipt-status', verifyAzureToken, async (req, res) => {
    try {
      const { status, to, reason } = req.body || {};
      const allowed = ['sent', 'no_email', 'error', 'pending'];
      if (!allowed.includes(status)) return res.status(400).json({ error: 'invalid status' });

      const at = status === 'sent' ? new Date().toISOString() : null;
      const finalReason = status === 'sent' || status === 'pending' ? null : (reason || null);
      await db.collection('members').doc(req.params.id).update({
        receiptEmailStatus: status,
        receiptEmailAt: at,
        receiptEmailTo: to || null,
        receiptEmailReason: finalReason,
      }).catch(() => {});
      try { lc.setMemberReceiptStatus?.(req.params.id, { status, to: to || null, at, reason: finalReason }); } catch (_) {}
      delete apiCache.profiles[req.params.id];

      if (status === 'error' || status === 'no_email') {
        try {
          const snap = await db.collection('members').doc(req.params.id).get();
          const m = snap.exists ? snap.data() : {};
          lc.addNotification?.({
            type: 'receipt_email_failed',
            gymId: m.location || '',
            title: `🧾 Reçu non envoyé — ${m.fullName || ''}`,
            message: finalReason
              ? `${finalReason} — reçu de paiement non envoyé. Corrigez l'email dans Paiements puis renvoyez-le.`
              : `Échec de l'envoi du reçu de paiement par email. Réessayez depuis Paiements.`,
            severity: 'critical',
            route: '/payments',
            icon: '🧾',
            refId: `receipt_fail_${req.params.id}`,
          });
        } catch (_) {}
      }
      res.json({ ok: true, status });
    } catch (e) {
      console.error('Receipt status error:', e.message);
      res.status(500).json({ error: e.message });
    }
  });


  // ── PATCH /api/members/:id/balance — Super Admin: set or adjust balance ───
  // Allows super admin to manually set or add a balance (reste) for a member.
  // This balance will automatically appear in the PWA Pay Reste list (/public/debtors).
  router.patch('/:id/balance', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const memberId = req.params.id;
      const { balance, balanceDeadline, note, mode } = req.body;
      // mode: 'set' (default) → replace, 'add' → add on top of existing
      if (balance === undefined || balance === null) {
        return res.status(400).json({ error: 'Missing balance amount' });
      }

      const ref = db.collection('members').doc(memberId);
      const snap = await ref.get();
      if (!snap.exists) return res.status(404).json({ error: 'Member not found' });

      const member = snap.data();
      const gymId = member.location || member.gymId || 'dokarat';

      // 🔒 Super admin: verify gym access
      if (!req.hasAccessToGym(gymId)) {
        return res.status(403).json({ error: 'Access Denied: You do not have access to this gym' });
      }

      const oldBalance = Number(member.balance || 0);
      const delta = Number(balance) || 0;
      const newBalance = mode === 'add'
        ? Math.max(0, oldBalance + delta)
        : Math.max(0, delta);

      const updateData = {
        balance: newBalance,
        balanceDeadline: balanceDeadline || null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        balanceLastEditedBy: req.user?.preferred_username || req.user?.name || 'SuperAdmin',
        balanceLastEditedAt: new Date().toISOString(),
        balanceNote: note || null,
      };

      await ref.update(updateData);

      // Write-through to SQLite
      try {
        const updatedSnap = await ref.get();
        lc.upsertMembers(gymId, [{ id: memberId, ...updatedSnap.data() }]);
      } catch (cacheErr) {
        console.warn('[balance-patch] SQLite sync failed:', cacheErr.message);
      }

      // Invalidate profile cache
      delete apiCache.profiles[memberId];

      console.log(`[BALANCE EDIT] ${req.user?.name || 'Admin'} set balance for ${member.fullName} (${gymId}): ${oldBalance} → ${newBalance} DH (mode: ${mode || 'set'})`);

      res.json({ ok: true, memberId, oldBalance, newBalance, balanceDeadline: balanceDeadline || null });
    } catch (err) {
      console.error('Balance Patch Error:', err);
      res.status(500).json({ error: 'Failed to update balance' });
    }
  });


  // ── PATCH /api/members/:id/contract — Admin-only: Fix contract data + PDF ──
  // Updates the confirmed member's contract fields and the stored PDF URL.
  // Only accessible to full admins. Logs the edit for audit trail.
  router.patch('/:id/contract', verifyAzureToken, async (req, res) => {
    try {
      const memberId = req.params.id;
      const {
        fullName, prenom, nom, phone, cin, birthday, email, adresse, ville,
        subscriptionName, subscriptionAmount, periodFrom, periodTo, expiresOn,
        commercial, payments, mentionParticulier, pdfUrl,
        contractEditedBy, contractEditedAt,
      } = req.body;

      // 🛡️ Admin-only guard
      if (!req.assignedGyms?.includes('all') && req.user?.role !== 'admin') {
        return res.status(403).json({ error: 'Accès refusé — réservé aux administrateurs' });
      }

      if (!memberId) return res.status(400).json({ error: 'memberId required' });

      const memberRef = db.collection('members').doc(memberId);
      const snap = await memberRef.get();
      if (!snap.exists) return res.status(404).json({ error: 'Membre introuvable' });

      const currentData = snap.data();
      const gymId = currentData?.location || currentData?.gymId || 'dokarat';
      const editorName = req.user?.preferred_username || req.user?.name || contractEditedBy || 'Admin';

      // 📜 Build PDF history — preserve old PDF before replacing
      const existingHistory = currentData.pdfHistory || [];
      const oldPdfUrl = currentData.pdfUrl;
      let newHistory = existingHistory;

      if (oldPdfUrl && pdfUrl && oldPdfUrl !== pdfUrl) {
        // Push old PDF into history with context info
        newHistory = [
          ...existingHistory,
          {
            url: oldPdfUrl,
            replacedAt: new Date().toISOString(),
            replacedBy: editorName,
            version: existingHistory.length + 1,
            previousSubscription: currentData.subscriptionName || null,
            previousPeriodFrom:   currentData.periodFrom || null,
            previousPeriodTo:     currentData.periodTo   || currentData.expiresOn || null,
          },
        ];
      }

      // Build update payload — only include defined values
      const updatePayload = {
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        contractCorrectedAt: admin.firestore.FieldValue.serverTimestamp(),
        contractCorrectedBy: editorName,
        pdfHistory: newHistory, // always write (even if empty array, keeps it clean)
      };

      if (fullName !== undefined)           updatePayload.fullName = fullName;
      if (prenom !== undefined)             updatePayload.prenom = prenom;
      if (nom !== undefined)                updatePayload.nom = nom;
      if (phone !== undefined)              updatePayload.phone = phone;
      if (cin !== undefined)                updatePayload.cin = cin;
      if (birthday !== undefined)           updatePayload.birthday = birthday;
      if (email !== undefined)              updatePayload.email = email;
      if (adresse !== undefined)            updatePayload.adresse = adresse;
      if (ville !== undefined)              updatePayload.ville = ville;
      if (subscriptionName !== undefined)   updatePayload.subscriptionName = subscriptionName;
      if (subscriptionAmount !== undefined) updatePayload.subscriptionAmount = Number(subscriptionAmount) || 0;
      if (periodFrom !== undefined)         updatePayload.periodFrom = periodFrom;
      if (periodTo !== undefined)           updatePayload.periodTo = periodTo;
      if (expiresOn !== undefined)          updatePayload.expiresOn = expiresOn;
      if (commercial !== undefined)         updatePayload.commercial = commercial;
      if (payments !== undefined)           updatePayload.payments = payments;
      if (mentionParticulier !== undefined) updatePayload.mentionParticulier = mentionParticulier;
      if (pdfUrl !== undefined)             updatePayload.pdfUrl = pdfUrl;

      await memberRef.update(updatePayload);

      // ✅ Write-through to SQLite members_cache
      try {
        const updated = await memberRef.get();
        lc.upsertMembers(gymId, [{ id: memberId, ...updated.data() }]);
      } catch (cacheErr) {
        console.warn('[contract-patch] SQLite sync failed:', cacheErr.message);
      }

      // Invalidate profile API cache
      try { delete apiCache.profiles?.[memberId]; } catch (_) {}

      console.log(`[CONTRACT FIX] Admin "${editorName}" corrected contract for member ${memberId} (${fullName || currentData?.fullName}). PDF history: ${newHistory.length} versions.`);

      res.json({ ok: true, memberId, pdfUrl, historyCount: newHistory.length });
    } catch (err) {
      console.error('Contract Patch Error:', err);
      res.status(500).json({ error: 'Failed to update contract', detail: err.message });
    }
  });


  // ── POST /api/members/backfill-photos ─────────────────────────────────────
  // One-click repair for BOTH confirmed members AND pending inscriptions that
  // show a placeholder. Photo sources, in order: existing base64/URL from the
  // inscription cache → the Firestore pending doc → and finally EXTRACTED FROM
  // THE PDF (the photo is embedded as a DCTDecode JPEG stream, so it survives
  // even when every other copy was wiped from Render's ephemeral disk). Admin only.
  router.post('/backfill-photos', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const gymId = req.body?.gymId && req.body.gymId !== 'all' ? req.body.gymId : null;

      const isUrl = (s) => typeof s === 'string' && /^https?:\/\//.test(s);
      const isData = (s) => typeof s === 'string' && s.startsWith('data:');
      // 🔒 SSRF guard: only ever fetch from Firebase/Google Storage hosts over
      // https — never an internal IP, metadata endpoint, or arbitrary host.
      const isStorageUrl = (s) => {
        try {
          const u = new URL(s);
          return u.protocol === 'https:' &&
            (u.hostname === 'firebasestorage.googleapis.com' || u.hostname === 'storage.googleapis.com' || u.hostname.endsWith('.storage.googleapis.com'));
        } catch { return false; }
      };

      // Pull the first embedded JPEG (profile photo) out of a jsPDF file and
      // re-upload it as a clean Storage image. Returns a URL or null.
      const photoFromPdf = async (pdfUrl, destPath) => {
        if (!isStorageUrl(pdfUrl)) return null; // SSRF guard
        try {
          const r = await fetch(pdfUrl);
          if (!r.ok) return null;
          const len = Number(r.headers.get('content-length') || 0);
          if (len > 25 * 1024 * 1024) return null; // cap: never buffer >25MB
          const buf = Buffer.from(await r.arrayBuffer());
          if (buf.length > 25 * 1024 * 1024) return null;
          const hay = buf.toString('latin1');
          const re = /DCTDecode[\s\S]*?stream\r?\n/g;
          let m;
          while ((m = re.exec(hay)) !== null) {
            const start = m.index + m[0].length;
            const end = hay.indexOf('endstream', start);
            if (end < 0) continue;
            const bytes = buf.subarray(start, end);
            if (bytes[0] === 0xff && bytes[1] === 0xd8) { // JPEG SOI — the profile photo
              const clean = await sharp(bytes).resize(320, 320, { fit: 'cover' }).jpeg({ quality: 78 }).toBuffer();
              return await uploadBase64ToStorage('data:image/jpeg;base64,' + clean.toString('base64'), destPath);
            }
          }
        } catch (e) { console.warn('[backfill] pdf extract failed:', e.message); }
        return null;
      };

      // Turn any raw source (base64 / url) into a Storage URL.
      const toUrl = async (raw, destPath) => {
        if (isUrl(raw)) return raw;
        if (isData(raw)) return await uploadBase64ToStorage(raw, destPath);
        return null;
      };

      let scanned = 0, fixed = 0, fromPdf = 0, noSource = 0, errors = 0;

      // ── 1) Confirmed members with no photo ──────────────────────────────────
      const memberRows = lc.db.prepare(
        `SELECT id, inscription_id, contract_number, pdf_url FROM members_cache
         WHERE (photo IS NULL OR photo = '') ${gymId ? 'AND gym_id = ?' : ''} LIMIT 400`
      ).all(...(gymId ? [gymId] : []));

      const findInscriptionPhoto = async (insId, contract) => {
        if (insId) {
          const p = lc.getPendingById(insId);
          if (p?.profile_picture) return { raw: p.profile_picture, pdf: p.pdf_url };
          try { const d = await db.collection('pending_members').doc(insId).get(); if (d.exists) { const x = d.data(); return { raw: x.profilePicture || x.photoUrl, pdf: x.pdfUrl }; } } catch (_) {}
        }
        if (contract) {
          try {
            const q = await db.collection('pending_members').where('contractNumber', '==', contract).limit(1).get();
            if (!q.empty) { const x = q.docs[0].data(); const p = lc.getPendingById(q.docs[0].id); return { raw: x.profilePicture || x.photoUrl || p?.profile_picture, pdf: x.pdfUrl || p?.pdf_url }; }
          } catch (_) {}
        }
        return { raw: null, pdf: null };
      };

      for (const m of memberRows) {
        scanned++;
        try {
          const src = await findInscriptionPhoto(m.inscription_id, m.contract_number);
          let url = await toUrl(src.raw, `members/${m.id}/profile_repair_${Date.now()}.jpg`);
          if (!url) { // last resort: extract from the PDF
            url = await photoFromPdf(src.pdf || m.pdf_url, `members/${m.id}/profile_frompdf_${Date.now()}.jpg`);
            if (url) fromPdf++;
          }
          if (!url) { noSource++; continue; }
          await db.collection('members').doc(m.id).update({ photo: url, photoRepairedAt: admin.firestore.FieldValue.serverTimestamp() });
          try { lc.db.prepare('UPDATE members_cache SET photo = ? WHERE id = ?').run(url, m.id); } catch (_) {}
          if (apiCache?.profiles) delete apiCache.profiles[m.id];
          fixed++;
        } catch (e) { errors++; console.warn('[backfill] member', m.id, e.message); }
      }

      // ── 2) Pending inscriptions with no photo but a PDF ─────────────────────
      const pendRows = lc.db.prepare(
        `SELECT id, pdf_url, profile_picture FROM pending_cache
         WHERE (profile_picture IS NULL OR profile_picture = '') AND pdf_url IS NOT NULL AND pdf_url != ''
         ${gymId ? 'AND gym_id = ?' : ''} LIMIT 400`
      ).all(...(gymId ? [gymId] : []));

      for (const p of pendRows) {
        scanned++;
        try {
          let pdf = p.pdf_url;
          if (!isUrl(pdf)) { try { const d = await db.collection('pending_members').doc(p.id).get(); if (d.exists) pdf = d.data().pdfUrl; } catch (_) {} }
          const url = await photoFromPdf(pdf, `inscriptions/repair/${p.id}_${Date.now()}.jpg`);
          if (!url) { noSource++; continue; }
          try { await db.collection('pending_members').doc(p.id).update({ profilePicture: url }); } catch (_) {}
          try { lc.db.prepare('UPDATE pending_cache SET profile_picture = ? WHERE id = ?').run(url, p.id); } catch (_) {}
          fixed++; fromPdf++;
        } catch (e) { errors++; console.warn('[backfill] pending', p.id, e.message); }
      }
      if (apiCache?.inscriptions) apiCache.inscriptions = {}; // force fresh pending list

      console.log(`[backfill-photos] scanned=${scanned} fixed=${fixed} fromPdf=${fromPdf} noSource=${noSource} errors=${errors}`);
      res.json({ ok: true, scanned, fixed, fromPdf, noSource, errors });
    } catch (err) {
      console.error('[backfill-photos] error:', err);
      res.status(500).json({ error: 'Failed to backfill photos' });
    }
  });


  return router;
};

