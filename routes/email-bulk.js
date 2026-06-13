'use strict';
// routes/email-bulk.js — MegaFit Bulk Email Campaign API
// Super admin only. Sends branded emails via notification@megafit.ma

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');
const { cleanEmail, sendBulkEmails, sendEmail } = require('../services/email-service');
const crypto = require('crypto');

module.exports = function emailBulkRouter({ lc }) {
  const router = Router();

  // ── GET /api/emails/recipients ─────────────────────────────────────────────
  router.get('/api/emails/recipients', verifyAzureToken, requireAdmin, (req, res) => {
    try {
      const gymFilter = req.query.gym || 'all';
      const raw = lc.getDistinctEmails(gymFilter);

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

      const raw = lc.getDistinctEmails(gymFilter || 'all');
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

      // Respond immediately
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
