'use strict';
// routes/email-bulk.js — MegaFit Bulk Email Campaign API v2
// Supports: templates, custom email lists, image uploads, persistent queue

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');
const { cleanEmail, sendBulkEmails, sendEmail, TEMPLATES, BANNER_URL } = require('../services/email-service');
const crypto = require('crypto');

const GYM_ALIASES = {
  'dokarat': ['dokarat', 'dokkarat', 'doukkarate'],
  'marjane': ['marjane', 'saiss'],
  'casa1':   ['casa1', 'casa anfa', 'anfa'],
  'casa2':   ['casa2', 'lady anfa', 'lady'],
};

function resolveGymId(location) {
  if (!location) return '';
  const l = location.toLowerCase().trim();
  for (const [gymId, aliases] of Object.entries(GYM_ALIASES)) {
    if (aliases.some(a => l.includes(a) || l === a)) return gymId;
  }
  return l;
}

async function getAllEmails(db, lc, gymFilter) {
  const emailMap = new Map();

  try {
    const membersSnap = await db.collection('members')
      .where('email', '!=', null)
      .select('email', 'fullName', 'location', 'gymId')
      .get();
    membersSnap.forEach(doc => {
      const d = doc.data();
      const email = (d.email || '').trim().toLowerCase();
      if (!email) return;
      const gymId = resolveGymId(d.location || d.gymId || '');
      if (gymFilter && gymFilter !== 'all' && gymId !== gymFilter) return;
      if (!emailMap.has(email)) emailMap.set(email, { email, name: d.fullName || '', gymId });
    });
  } catch (err) { console.warn('[EMAIL] Firestore members:', err.message); }

  try {
    const pendingSnap = await db.collection('pending_members')
      .where('email', '!=', null)
      .select('email', 'nom', 'prenom', 'gymId')
      .get();
    pendingSnap.forEach(doc => {
      const d = doc.data();
      const email = (d.email || '').trim().toLowerCase();
      if (!email) return;
      const gymId = resolveGymId(d.gymId || '');
      if (gymFilter && gymFilter !== 'all' && gymId !== gymFilter) return;
      const name = `${d.prenom || ''} ${d.nom || ''}`.trim();
      if (!emailMap.has(email)) emailMap.set(email, { email, name, gymId });
    });
  } catch (err) { console.warn('[EMAIL] Firestore pending:', err.message); }

  try {
    const sqliteEmails = lc.getDistinctEmails(gymFilter || 'all');
    for (const r of sqliteEmails) {
      const email = (r.email || '').trim().toLowerCase();
      if (!email || emailMap.has(email)) continue;
      emailMap.set(email, { email, name: r.name || '', gymId: r.gymId || '' });
    }
  } catch (err) { console.warn('[EMAIL] SQLite:', err.message); }

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
      const gymCounts = {};

      for (const r of raw) {
        const cleaned = cleanEmail(r.email);
        if (cleaned) {
          if (cleaned !== r.email.trim().toLowerCase()) fixed++;
          valid++;
          gymCounts[r.gymId] = (gymCounts[r.gymId] || 0) + 1;
        } else {
          invalid++;
        }
      }

      res.json({ total: raw.length, valid, invalid, fixed, gymCounts });
    } catch (err) {
      console.error('[EMAIL-BULK recipients]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/emails/templates ──────────────────────────────────────────────
  router.get('/api/emails/templates', verifyAzureToken, requireAdmin, (req, res) => {
    const list = Object.entries(TEMPLATES).map(([id, t]) => ({
      id, label: t.label, icon: t.icon, accent: t.accent,
    }));
    res.json({ templates: list, bannerUrl: BANNER_URL });
  });

  // ── POST /api/emails/send-bulk ─────────────────────────────────────────────
  // Supports: gymFilter, customEmails (array), template, imageUrl, ctaText, ctaUrl
  router.post('/api/emails/send-bulk', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { subject, html, gymFilter, customEmails, template, imageUrl, ctaText, ctaUrl } = req.body;
      if (!subject?.trim()) return res.status(400).json({ error: 'Sujet requis' });
      if (!html?.trim()) return res.status(400).json({ error: 'Contenu requis' });

      let recipients = [];

      // Custom emails (manual list)
      if (customEmails && Array.isArray(customEmails) && customEmails.length > 0) {
        for (const entry of customEmails) {
          const email = typeof entry === 'string' ? entry : entry.email;
          const name = typeof entry === 'string' ? '' : (entry.name || '');
          const cleaned = cleanEmail(email);
          if (cleaned) recipients.push({ email: cleaned, name, gymId: 'custom' });
        }
      } else {
        // Database emails
        const raw = await getAllEmails(db, lc, gymFilter || 'all');
        for (const r of raw) {
          const cleaned = cleanEmail(r.email);
          if (cleaned) recipients.push({ email: cleaned, name: r.name, gymId: r.gymId });
        }
      }

      if (recipients.length === 0) return res.status(400).json({ error: 'Aucun destinataire valide' });

      const campaignId = `campaign_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const options = { template: template || 'announcement', imageUrl: imageUrl || null, ctaText: ctaText || '', ctaUrl: ctaUrl || '' };

      lc.upsertEmailCampaign({
        id: campaignId, subject: subject.trim(),
        bodyPreview: html.replace(/<[^>]+>/g, '').slice(0, 200),
        gymFilter: gymFilter || (customEmails ? 'custom' : 'all'),
        total: recipients.length,
        sent: 0, failed: 0, status: 'sending',
        createdAt: new Date().toISOString(),
      });

      // Save queue for recovery after server restart
      try {
        lc.db.prepare(`CREATE TABLE IF NOT EXISTS email_queue (
          campaign_id TEXT, email TEXT, name TEXT, gym_id TEXT,
          PRIMARY KEY (campaign_id, email)
        )`).run();
        const insertQueue = lc.db.prepare('INSERT OR IGNORE INTO email_queue (campaign_id, email, name, gym_id) VALUES (?, ?, ?, ?)');
        const saveQueue = lc.db.transaction((rows) => {
          for (const r of rows) insertQueue.run(campaignId, r.email, r.name, r.gymId);
        });
        saveQueue(recipients);
      } catch(_) {}

      res.json({ ok: true, campaignId, total: recipients.length, message: `Envoi lance: ${recipients.length} emails` });

      // Background send
      (async () => {
        try {
          console.log(`[Email ${campaignId}] Starting: ${recipients.length} recipients, template: ${options.template}`);
          const result = await sendBulkEmails(recipients, subject, html, (progress) => {
            try {
              lc.updateEmailCampaign(campaignId, { sent: progress.sent, failed: progress.failed });
              // Remove sent emails from queue
              try {
                lc.db.prepare('DELETE FROM email_queue WHERE campaign_id = ? AND email IN (' +
                  recipients.slice(0, progress.sent + progress.failed).map(() => '?').join(',') + ')')
                  .run(campaignId, ...recipients.slice(0, progress.sent + progress.failed).map(r => r.email));
              } catch(_) {}
            } catch(_) {}
          }, options);

          const finalStatus = result.rateLimited ? 'rate_limited' : 'completed';
          lc.updateEmailCampaign(campaignId, {
            sent: result.sent, failed: result.failed, status: finalStatus,
            completedAt: new Date().toISOString(),
            errors: result.errors.length > 0 ? result.errors.slice(0, 20) : null,
          });

          // Clear queue on completion
          if (!result.rateLimited) {
            try { lc.db.prepare('DELETE FROM email_queue WHERE campaign_id = ?').run(campaignId); } catch(_) {}
          }

          console.log(`[Email ${campaignId}] Done: ${result.sent}/${recipients.length} sent`);

          try {
            lc.addNotification({
              type: 'email_campaign', gymId: gymFilter || 'all',
              title: `Campagne email ${finalStatus === 'completed' ? 'terminee' : 'limitee'}`,
              message: `"${subject}" - ${result.sent} envoyes, ${result.failed} echoues sur ${recipients.length}`,
              severity: result.failed > 0 ? 'warning' : 'info', route: '/push', icon: 'email', refId: campaignId,
            });
          } catch(_) {}
        } catch (err) {
          console.error(`[Email ${campaignId}] FATAL:`, err);
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
      const campaigns = lc.getEmailCampaigns(20);
      // Check for queued (incomplete) campaigns
      try {
        const queueCounts = lc.db.prepare(
          'SELECT campaign_id, COUNT(*) as remaining FROM email_queue GROUP BY campaign_id'
        ).all();
        const queueMap = Object.fromEntries(queueCounts.map(q => [q.campaign_id, q.remaining]));
        for (const c of campaigns) {
          c.queued = queueMap[c.id] || 0;
        }
      } catch(_) {}
      res.json(campaigns);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/emails/resume ────────────────────────────────────────────────
  // Resume a rate-limited campaign from the queue
  router.post('/api/emails/resume', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { campaignId, subject, html, template, imageUrl, ctaText, ctaUrl } = req.body;
      if (!campaignId) return res.status(400).json({ error: 'campaignId requis' });

      const queued = lc.db.prepare('SELECT * FROM email_queue WHERE campaign_id = ?').all(campaignId);
      if (queued.length === 0) return res.json({ ok: true, message: 'Rien a reprendre', remaining: 0 });

      const recipients = queued.map(q => ({ email: q.email, name: q.name, gymId: q.gym_id }));
      const options = { template: template || 'announcement', imageUrl, ctaText, ctaUrl };

      lc.updateEmailCampaign(campaignId, { status: 'sending' });
      res.json({ ok: true, resuming: recipients.length });

      // Background send
      (async () => {
        const result = await sendBulkEmails(recipients, subject || 'MegaFit', html || '<p>Message</p>', null, options);
        const campaign = lc.db.prepare('SELECT * FROM email_campaigns WHERE id = ?').get(campaignId);
        const prevSent = campaign ? campaign.sent : 0;
        const prevFailed = campaign ? campaign.failed : 0;

        lc.updateEmailCampaign(campaignId, {
          sent: prevSent + result.sent,
          failed: prevFailed + result.failed,
          status: result.rateLimited ? 'rate_limited' : 'completed',
          completedAt: new Date().toISOString(),
        });

        if (!result.rateLimited) {
          try { lc.db.prepare('DELETE FROM email_queue WHERE campaign_id = ?').run(campaignId); } catch(_) {}
        }
      })();
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/emails/send-test ─────────────────────────────────────────────
  router.post('/api/emails/send-test', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { to, subject, html, template, imageUrl, ctaText, ctaUrl } = req.body;
      if (!to || !subject || !html) return res.status(400).json({ error: 'to, subject, html requis' });
      const options = { template: template || 'announcement', imageUrl, ctaText, ctaUrl };
      const result = await sendEmail(to, subject, html, 'Admin', options);
      res.json({ ok: true, ...result });
    } catch (err) {
      console.error('[EMAIL-BULK send-test]', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── On server startup: resume incomplete campaigns ─────────────────────────
  setTimeout(() => {
    try {
      const incomplete = lc.getEmailCampaigns(5).filter(c => c.status === 'sending' || c.status === 'rate_limited');
      for (const c of incomplete) {
        try {
          const queued = lc.db.prepare('SELECT COUNT(*) as n FROM email_queue WHERE campaign_id = ?').get(c.id);
          if (queued && queued.n > 0) {
            console.log(`[EMAIL] Found incomplete campaign ${c.id}: ${queued.n} emails remaining. Will retry on next manual resume.`);
            lc.updateEmailCampaign(c.id, { status: 'rate_limited' });
          } else {
            lc.updateEmailCampaign(c.id, { status: 'completed', completedAt: new Date().toISOString() });
          }
        } catch(_) {}
      }
    } catch(_) {}
  }, 5000);

  return router;
};
