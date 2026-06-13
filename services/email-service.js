'use strict';
// services/email-service.js — MegaFit Bulk Email Service
// Uses Nodemailer with cPanel SMTP (notification@megafit.ma)
// Supports batch sending with rate limiting + background queue

const nodemailer = require('nodemailer');

// ─── SMTP Config ──────────────────────────────────────────────────────────────
const SMTP_HOST = process.env.SMTP_HOST || 'mail.megafit.ma';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_USER = process.env.SMTP_USER || 'notification@megafit.ma';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = `"MegaFit" <${SMTP_USER}>`;

// cPanel limit: ~300/hour → safe batch: 40 per batch, 6s delay = ~400/hour max
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
  'gmail.co': 'gmail.com', 'gmail.fr': 'gmail.com', 'gmail.con': 'gmail.com',
  'hotmial.com': 'hotmail.com', 'hotmal.com': 'hotmail.com', 'hotmil.com': 'hotmail.com',
  'hotmail.fr': 'hotmail.fr', 'hotmail.con': 'hotmail.com',
  'outloo.com': 'outlook.com', 'outlok.com': 'outlook.com',
  'yahooo.com': 'yahoo.com', 'yaho.com': 'yahoo.com', 'yahoo.fr': 'yahoo.fr',
  'iclod.com': 'icloud.com', 'icoud.com': 'icloud.com',
};

function cleanEmail(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let email = raw.trim().toLowerCase().replace(/\s+/g, '');

  // Remove leading/trailing dots or commas
  email = email.replace(/^[.,]+|[.,]+$/g, '');

  // Fix missing @ — if there's no @ but domain-like string exists
  if (!email.includes('@')) return null;

  // Fix double @
  email = email.replace(/@@+/g, '@');

  // Fix common domain typos
  const parts = email.split('@');
  if (parts.length !== 2) return null;

  const [local, domain] = parts;
  if (!local || !domain) return null;

  const fixedDomain = TYPO_FIXES[domain] || domain;
  email = `${local}@${fixedDomain}`;

  // Final validation
  if (!EMAIL_REGEX.test(email)) return null;
  if (email.length > 254) return null;

  // Filter obvious fakes
  const fakePatterns = [
    /^test@/, /^fake@/, /^abc@/, /^123@/, /^aaa@/, /^xxx@/,
    /^no@/, /^non@/, /^rien@/, /^pas@/, /^none@/,
    /@test\.com$/, /@fake\.com$/, /@example\.com$/,
  ];
  for (const p of fakePatterns) {
    if (p.test(email)) return null;
  }

  return email;
}

// ─── HTML Template ────────────────────────────────────────────────────────────
function buildHtmlEmail(subject, bodyHtml, recipientName) {
  const firstName = recipientName
    ? recipientName.split(' ')[0]
    : 'Membre';

  const processedBody = bodyHtml
    .replace(/\{firstname\}/gi, firstName)
    .replace(/\[firstname\]/gi, firstName)
    .replace(/\{name\}/gi, recipientName || 'Membre')
    .replace(/\[name\]/gi, recipientName || 'Membre');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background:#0f0f14;font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f0f14;padding:30px 10px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
          
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-radius:16px 16px 0 0;padding:28px 32px;text-align:center;">
              <div style="font-size:28px;font-weight:900;color:#22c55e;letter-spacing:3px;margin-bottom:4px;">
                MEGAFIT
              </div>
              <div style="font-size:11px;color:#64748b;letter-spacing:2px;text-transform:uppercase;">
                Votre réseau fitness premium
              </div>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="background:#1a1a28;padding:32px;color:#e2e8f0;font-size:15px;line-height:1.7;">
              ${processedBody}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#12121a;border-radius:0 0 16px 16px;padding:24px 32px;text-align:center;">
              <div style="font-size:11px;color:#4b5563;line-height:1.6;">
                MegaFit — Dokkarat · Saïss · Anfa · Lady Anfa<br>
                Cet email a été envoyé à ${recipientName || 'vous'} par MegaFit.<br>
                <a href="mailto:notification@megafit.ma" style="color:#8b5cf6;text-decoration:none;">notification@megafit.ma</a>
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
async function sendEmail(to, subject, htmlBody, recipientName) {
  const transport = getTransporter();
  const html = buildHtmlEmail(subject, htmlBody, recipientName);

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
async function sendBulkEmails(recipients, subject, htmlBody, onProgress) {
  // recipients = [{ email, name, gymId }]
  const transport = getTransporter();
  let sent = 0, failed = 0, errors = [];

  const total = recipients.length;

  for (let i = 0; i < total; i += BATCH_SIZE) {
    const batch = recipients.slice(i, i + BATCH_SIZE);

    for (const r of batch) {
      try {
        const html = buildHtmlEmail(subject, htmlBody, r.name);
        await transport.sendMail({
          from: SMTP_FROM,
          to: r.email,
          subject: subject
            .replace(/\{firstname\}/gi, (r.name || 'Membre').split(' ')[0])
            .replace(/\[firstname\]/gi, (r.name || 'Membre').split(' ')[0]),
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
        // If connection error, stop and queue the rest
        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.responseCode === 421) {
          return { sent, failed, errors, remaining: recipients.slice(i + batch.indexOf(r) + 1), rateLimited: true };
        }
      }
    }

    // Progress callback
    if (onProgress) onProgress({ sent, failed, total, batch: Math.floor(i / BATCH_SIZE) + 1 });

    // Delay between batches (respect rate limit)
    if (i + BATCH_SIZE < total) {
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY_MS));
    }
  }

  return { sent, failed, errors, remaining: [], rateLimited: false };
}

module.exports = { cleanEmail, sendEmail, sendBulkEmails, buildHtmlEmail, BATCH_SIZE, BATCH_DELAY_MS };
