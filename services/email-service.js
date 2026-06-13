'use strict';
// services/email-service.js — MegaFit Bulk Email Service v2
// Premium HTML templates, image support, batch sending with persistent queue

const nodemailer = require('nodemailer');

// ─── SMTP Config ──────────────────────────────────────────────────────────────
const SMTP_HOST = process.env.SMTP_HOST || 'mail.megafit.ma';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_USER = process.env.SMTP_NOTIF_USER || process.env.SMTP_USER || 'notification@megafit.ma';
const SMTP_PASS = process.env.SMTP_NOTIF_PASS || process.env.SMTP_PASS || '';
const SMTP_FROM = `"MegaFit" <${SMTP_USER}>`;

// Banner hosted on dashboard (public, accessible by email clients)
const BANNER_URL = 'https://megafitauth.web.app/images/megafit-banner.png';

// cPanel limit: ~300/hour → safe batch: 40 per batch, 6s delay
const BATCH_SIZE = 40;
const BATCH_DELAY_MS = 6000;

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (!SMTP_PASS) throw new Error('SMTP_PASS not configured');

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    tls: { rejectUnauthorized: false },
    pool: true,
    maxConnections: 3,
    maxMessages: 50,
    rateDelta: 2000,
    rateLimit: 5,
  });

  return transporter;
}

// ─── Email Validation ─────────────────────────────────────────────────────────
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const TYPO_FIXES = {
  'gmial.com': 'gmail.com', 'gmal.com': 'gmail.com', 'gmaill.com': 'gmail.com',
  'gamil.com': 'gmail.com', 'gnail.com': 'gmail.com', 'gmai.com': 'gmail.com',
  'gmail.co': 'gmail.com', 'gmail.con': 'gmail.com',
  'hotmial.com': 'hotmail.com', 'hotmal.com': 'hotmail.com', 'hotmil.com': 'hotmail.com',
  'hotmail.con': 'hotmail.com',
  'outloo.com': 'outlook.com', 'outlok.com': 'outlook.com',
  'yahooo.com': 'yahoo.com', 'yaho.com': 'yahoo.com',
  'iclod.com': 'icloud.com', 'icoud.com': 'icloud.com',
};

function cleanEmail(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let email = raw.trim().toLowerCase().replace(/\s+/g, '');
  email = email.replace(/^[.,]+|[.,]+$/g, '');
  if (!email.includes('@')) return null;
  email = email.replace(/@@+/g, '@');
  const parts = email.split('@');
  if (parts.length !== 2) return null;
  const [local, domain] = parts;
  if (!local || !domain) return null;
  const fixedDomain = TYPO_FIXES[domain] || domain;
  email = `${local}@${fixedDomain}`;
  if (!EMAIL_REGEX.test(email)) return null;
  if (email.length > 254) return null;

  const fakePatterns = [
    /^test@/, /^fake@/, /^abc@/, /^123@/, /^aaa@/, /^xxx@/,
    /^no@/, /^non@/, /^rien@/, /^pas@/, /^none@/,
    /@test\.com$/, /@fake\.com$/, /@example\.com$/,
  ];
  for (const p of fakePatterns) { if (p.test(email)) return null; }
  return email;
}

// ─── Template Types ───────────────────────────────────────────────────────────
const TEMPLATES = {
  announcement: {
    accent: '#6366f1',
    accentLight: 'rgba(99,102,241,0.15)',
    icon: '📢',
    label: 'Annonce',
  },
  offer: {
    accent: '#22c55e',
    accentLight: 'rgba(34,197,94,0.15)',
    icon: '🔥',
    label: 'Offre',
  },
  challenge: {
    accent: '#f59e0b',
    accentLight: 'rgba(245,158,11,0.15)',
    icon: '🏆',
    label: 'Challenge',
  },
  event: {
    accent: '#ec4899',
    accentLight: 'rgba(236,72,153,0.15)',
    icon: '🎉',
    label: 'Événement',
  },
  info: {
    accent: '#3b82f6',
    accentLight: 'rgba(59,130,246,0.15)',
    icon: 'ℹ️',
    label: 'Information',
  },
  reminder: {
    accent: '#8b5cf6',
    accentLight: 'rgba(139,92,246,0.15)',
    icon: '⏰',
    label: 'Rappel',
  },
};

// ─── Premium HTML Template ────────────────────────────────────────────────────
function buildHtmlEmail(subject, bodyHtml, recipientName, options = {}) {
  const { template = 'announcement', imageUrl = null, ctaText = '', ctaUrl = '' } = options;
  const tmpl = TEMPLATES[template] || TEMPLATES.announcement;

  const firstName = recipientName
    ? recipientName.split(' ')[0]
    : 'Membre';

  const processedBody = bodyHtml
    .replace(/\{firstname\}/gi, firstName)
    .replace(/\[firstname\]/gi, firstName)
    .replace(/\{name\}/gi, recipientName || 'Membre')
    .replace(/\[name\]/gi, recipientName || 'Membre');

  const imageBlock = imageUrl ? `
    <tr>
      <td style="padding:0;">
        <img src="${imageUrl}" alt="" style="width:100%;height:auto;display:block;border-radius:0;" />
      </td>
    </tr>` : '';

  const ctaBlock = (ctaText && ctaUrl) ? `
    <tr>
      <td style="padding:24px 32px 8px;text-align:center;">
        <a href="${ctaUrl}" style="
          display:inline-block;padding:16px 40px;
          background:${tmpl.accent};color:#ffffff;
          border-radius:14px;text-decoration:none;
          font-weight:900;font-size:16px;letter-spacing:0.5px;
          box-shadow:0 4px 16px ${tmpl.accent}40;
        ">${ctaText}</a>
      </td>
    </tr>` : '';

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background:#0a0a12;font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a12;padding:24px 8px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;border-radius:20px;overflow:hidden;box-shadow:0 8px 40px rgba(0,0,0,0.5);">

          <!-- Banner -->
          <tr>
            <td style="background:#000;padding:20px 24px 12px;text-align:center;">
              <img src="${BANNER_URL}" alt="MegaFit" style="max-width:220px;height:auto;display:inline-block;" />
            </td>
          </tr>

          <!-- Accent Line -->
          <tr>
            <td style="height:3px;background:linear-gradient(90deg, ${tmpl.accent}, ${tmpl.accent}80, transparent);"></td>
          </tr>

          <!-- Template Badge -->
          <tr>
            <td style="background:#111118;padding:16px 32px 4px;">
              <div style="display:inline-block;padding:6px 14px;border-radius:10px;background:${tmpl.accentLight};border:1px solid ${tmpl.accent}30;font-size:12px;font-weight:800;color:${tmpl.accent};letter-spacing:0.5px;">
                ${tmpl.icon} ${tmpl.label.toUpperCase()}
              </div>
            </td>
          </tr>

          ${imageBlock}

          <!-- Body -->
          <tr>
            <td style="background:#111118;padding:20px 32px 28px;color:#d1d5db;font-size:15px;line-height:1.8;">
              ${processedBody}
            </td>
          </tr>

          ${ctaBlock}

          <!-- Spacer -->
          <tr><td style="background:#111118;height:16px;"></td></tr>

          <!-- Footer -->
          <tr>
            <td style="background:#0a0a10;padding:20px 32px;text-align:center;border-top:1px solid rgba(255,255,255,0.05);">
              <div style="font-size:11px;color:#4b5563;line-height:1.6;">
                <strong style="color:#6b7280;">MegaFit</strong> — Dokkarat · Saïss · Anfa · Lady Anfa<br>
                📧 notification@megafit.ma · 🌐 megafit.ma<br><br>
                <span style="font-size:10px;color:#374151;">
                  Vous recevez cet email car vous êtes membre de MegaFit.<br>
                  Pour ne plus recevoir ces emails, répondez "STOP".
                </span>
              </div>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ─── Send Single Email ────────────────────────────────────────────────────────
async function sendEmail(to, subject, htmlBody, recipientName, options = {}) {
  const transport = getTransporter();
  const html = buildHtmlEmail(subject, htmlBody, recipientName, options);

  const info = await transport.sendMail({
    from: SMTP_FROM,
    to,
    subject,
    html,
    headers: {
      'X-Mailer': 'MegaFit Notification System',
      'List-Unsubscribe': `<mailto:${SMTP_USER}?subject=unsubscribe>`,
    },
  });

  return { messageId: info.messageId, accepted: info.accepted, rejected: info.rejected };
}

// ─── Bulk Sender (with rate limiting) ─────────────────────────────────────────
async function sendBulkEmails(recipients, subject, htmlBody, onProgress, options = {}) {
  const transport = getTransporter();
  let sent = 0, failed = 0, errors = [];
  const total = recipients.length;

  for (let i = 0; i < total; i += BATCH_SIZE) {
    const batch = recipients.slice(i, i + BATCH_SIZE);

    for (const r of batch) {
      try {
        const html = buildHtmlEmail(subject, htmlBody, r.name, options);
        const personalSubject = subject
          .replace(/\{firstname\}/gi, (r.name || 'Membre').split(' ')[0])
          .replace(/\[firstname\]/gi, (r.name || 'Membre').split(' ')[0]);

        await transport.sendMail({
          from: SMTP_FROM,
          to: r.email,
          subject: personalSubject,
          html,
          headers: {
            'X-Mailer': 'MegaFit Notification System',
            'List-Unsubscribe': `<mailto:${SMTP_USER}?subject=unsubscribe>`,
          },
        });
        sent++;
      } catch (err) {
        failed++;
        errors.push({ email: r.email, error: err.message });
        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.responseCode === 421) {
          return { sent, failed, errors, remaining: recipients.slice(i + batch.indexOf(r) + 1), rateLimited: true };
        }
      }
    }

    if (onProgress) onProgress({ sent, failed, total, batch: Math.floor(i / BATCH_SIZE) + 1 });

    if (i + BATCH_SIZE < total) {
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY_MS));
    }
  }

  return { sent, failed, errors, remaining: [], rateLimited: false };
}

module.exports = { cleanEmail, sendEmail, sendBulkEmails, buildHtmlEmail, TEMPLATES, BATCH_SIZE, BATCH_DELAY_MS, BANNER_URL };
