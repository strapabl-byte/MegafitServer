'use strict';
// routes/email-bulk.js — MegaFit Bulk Email Campaign API
// Super admin only. Sends branded emails via notification@megafit.ma
// Sources: Firestore members collection (14k+) + SQLite cache (pending inscriptions)

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');
const { cleanEmail, sendBulkEmails, sendEmail } = require('../services/email-service');
const crypto = require('crypto');

// GYM_ID mapping for Firestore members (they use 'location' field)
const GYM_ALIASES = {
  'dokarat': ['dokarat', 'dokkarat', 'doukkarate'],
  'marjane': ['marjane', 'saiss', 'saïss'],
  'casa1':   ['casa1', 'casa anfa', 'anfa'],
  'casa2':   ['casa2', 'lady anfa', 'lady', 'casa lady'],
};

function resolveGymId(location) {
  if (!location) return '';
  const l = location.toLowerCase().trim();
  for (const [gymId, aliases] of Object.entries(GYM_ALIASES)) {
    if (aliases.some(a => l.includes(a) || l === a)) return gymId;
  }
  return l;
}

// Collect ALL emails from Firestore + SQLite
async function getAllEmails(db, lc, gymFilter) {
  const emailMap = new Map(); // email → { email, name, gymId }

  // 1. Firestore members (the main 14k+ database)
  try {
    const membersSnap = await db.collection('members')
      .where('email', '!=', null)
      .select('email', 'fullName', 'location', 'gymId')
      .get();

    console.log(`[EMAIL] Firestore members with email field: ${membersSnap.size}`);

    membersSnap.forEach(doc => {
      const d = doc.data();
      const email = (d.email || '').trim().toLowerCase();
      if (!email) return;
      const gymId = resolveGymId(d.location || d.gymId || '');
      if (gymFilter && gymFilter !== 'all' && gymId !== gymFilter) return;
      if (!emailMap.has(email)) {
        emailMap.set(email, { email, name: d.fullName || '', gymId });
      }
    });
  } catch (err) {
    console.warn('[EMAIL] Firestore members query failed:', err.message);
  }

  // 2. Firestore pending_members (unconfirmed inscriptions may have emails too)
  try {
    const pendingSnap = await db.collection('pending_members')
      .where('email', '!=', null)
      .select('email', 'nom', 'prenom', 'gymId')
      .get();

    console.log(`[EMAIL] Firestore pending_members with email: ${pendingSnap.size}`);

    pendingSnap.forEach(doc => {
      const d = doc.data();
      const email = (d.email || '').trim().toLowerCase();
      if (!email) return;
      const gymId = resolveGymId(d.gymId || '');
      if (gymFilter && gymFilter !== 'all' && gymId !== gymFilter) return;
      const name = `${d.prenom || ''} ${d.nom || ''}`.trim();
      if (!emailMap.has(email)) {
        emailMap.set(email, { email, name, gymId });
      }
    });
  } catch (err) {
    console.warn('[EMAIL] Firestore pending query failed:', err.message);
  }

  // 3. SQLite cache (backup — catches anything synced locally)
  try {
    const sqliteEmails = lc.getDistinctEmails(gymFilter || 'all');
    for (const r of sqliteEmails) {
      const email = (r.email || '').trim().toLowerCase();
      if (!email || emailMap.has(email)) continue;
      emailMap.set(email, { email, name: r.name || '', gymId: r.gymId || '' });
    }
    console.log(`[EMAIL] SQLite added ${sqliteEmails.length} (after dedup: ${emailMap.size} total)`);
  } catch (err) {
    console.warn('[EMAIL] SQLite query failed:', err.message);
  }

  return Array.from(emailMap.values());
}

module.exports = function emailBulkRouter({ lc, db }) {
  const router = Router();

  // ── GET /api/emails/recipients ─────────────────────────────────────────────
  router.get('/api/emails/recipients', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const gymFilter = req.query.gym || 'all';
      const raw = await getAllEmails(db, lc, gymFilter);

      let valid = 0, invalid = 0, fixed = 0;
      const validEmails = [];
      const invalidEmails = [];
      const gymCounts = {};

      for (const r of raw) {
        const cleaned = cleanEmail(r.email);
        if (cleaned) {
          if (cleaned !== r.email.trim().toLowerCase()) fixed++;
          valid++;
          validEmails.push({ email: cleaned, name: r.name, gymId: r.gymId });
          gymCounts[r.gymId] = (gymCounts[r.gymId] || 0) + 1;
        } else {
          invalid++;
          invalidEmails.push({ email: r.email, name: r.name, gymId: r.gymId });
        }
      }

      res.json({ total: raw.length, valid, invalid, fixed, gymCounts, preview: validEmails.slice(0, 10), invalidPreview: invalidEmails.slice(0, 10) });
    } catch (err) {
      console.error('[EMAIL-BULK recipients]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/emails/send-bulk ─────────────────────────────────────────────
  router.post('/api/emails/send-bulk', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { subject, html, gymFilter } = req.body;
      if (!subject?.trim()) return res.status(400).json({ error: 'Sujet requis' });
      if (!html?.trim()) return res.status(400).json({ error: 'Contenu requis' });

      const raw = await getAllEmails(db, lc, gymFilter || 'all');
      const recipients = [];
      for (const r of raw) {
        const cleaned = cleanEmail(r.email);
        if (cleaned) recipients.push({ email: cleaned, name: r.name, gymId: r.gymId });
      }

      if (recipients.length === 0) return res.status(400).json({ error: 'Aucun destinataire valide' });

      const campaignId = `campaign_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      lc.upsertEmailCampaign({
        id: campaignId, subject: subject.trim(),
        bodyPreview: html.replace(/<[^>]+>/g, '').slice(0, 200),
        gymFilter: gymFilter || 'all', total: recipients.length,
        sent: 0, failed: 0, status: 'sending',
        createdAt: new Date().toISOString(),
      });

      res.json({ ok: true, campaignId, total: recipients.length, message: `Envoi lance: ${recipients.length} emails` });

      // Background send
      (async () => {
        try {
          console.log(`[Email Campaign ${campaignId}] Starting: ${recipients.length} recipients`);
          const result = await sendBulkEmails(recipients, subject, html, (progress) => {
            try { lc.updateEmailCampaign(campaignId, { sent: progress.sent, failed: progress.failed }); } catch(_) {}
          });

          const finalStatus = result.rateLimited ? 'rate_limited' : 'completed';
          lc.updateEmailCampaign(campaignId, {
            sent: result.sent, failed: result.failed, status: finalStatus,
            completedAt: new Date().toISOString(),
            errors: result.errors.length > 0 ? result.errors.slice(0, 20) : null,
          });

          console.log(`[Email Campaign ${campaignId}] Done: ${result.sent} sent, ${result.failed} failed`);

          try {
            lc.addNotification({
              type: 'email_campaign', gymId: gymFilter || 'all',
              title: `Campagne email ${finalStatus === 'completed' ? 'terminee' : 'limitee'}`,
              message: `"${subject}" - ${result.sent} envoyes, ${result.failed} echoues sur ${recipients.length}`,
              severity: result.failed > 0 ? 'warning' : 'info', route: '/push', icon: 'email', refId: campaignId,
            });
          } catch(_) {}
        } catch (err) {
          console.error(`[Email Campaign ${campaignId}] FATAL:`, err);
          try { lc.updateEmailCampaign(campaignId, { status: 'error', completedAt: new Date().toISOString(), errors: [{ error: err.message }] }); } catch(_) {}
        }
      })();
    } catch (err) {
      console.error('[EMAIL-BULK send-bulk]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/emails/campaigns ──────────────────────────────────────────────
  router.get('/api/emails/campaigns', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      res.json(lc.getEmailCampaigns(20));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/emails/send-test ─────────────────────────────────────────────
  router.post('/api/emails/send-test', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { to, subject, html } = req.body;
      if (!to || !subject || !html) return res.status(400).json({ error: 'to, subject, html requis' });
      const result = await sendEmail(to, subject, html, 'Admin');
      res.json({ ok: true, ...result });
    } catch (err) {
      console.error('[EMAIL-BULK send-test]', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
