'use strict';
// services/email-service.js — MegaFit Professional Email Service v3
// Clean, professional HTML templates — NO emojis in emails

const nodemailer = require('nodemailer');

// ─── SMTP Config ──────────────────────────────────────────────────────────────
const SMTP_HOST = process.env.SMTP_HOST || 'mail.megafit.ma';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_USER = process.env.SMTP_NOTIF_USER || process.env.SMTP_USER || 'notification@megafit.ma';
const SMTP_PASS = process.env.SMTP_NOTIF_PASS || process.env.SMTP_PASS || '';
const SMTP_FROM_EMAIL = process.env.SMTP_FROM_EMAIL || 'notification@megafit.ma';
const SMTP_FROM = `"MegaFit" <${SMTP_FROM_EMAIL}>`;

const BANNER_URL = 'https://megafitauth.web.app/images/megafit-banner.png';

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
// Each template has a distinct visual identity and use case
const TEMPLATES = {
  announcement: {
    accent: '#6366f1',
    label: 'Annonce Generale',
    labelAr: 'اعلان عام',
    tagline: 'Communication officielle',
  },
  offer: {
    accent: '#22c55e',
    label: 'Offre Promotionnelle',
    labelAr: 'عرض ترويجي',
    tagline: 'Offre exclusive pour nos membres',
  },
  challenge: {
    accent: '#f59e0b',
    label: 'Challenge Fitness',
    labelAr: 'تحدي اللياقة',
    tagline: 'Relevez le defi',
  },
  event: {
    accent: '#ec4899',
    label: 'Evenement',
    labelAr: 'حدث',
    tagline: 'A ne pas manquer',
  },
  info: {
    accent: '#3b82f6',
    label: 'Information',
    labelAr: 'معلومات',
    tagline: 'Information importante',
  },
  reminder: {
    accent: '#8b5cf6',
    label: 'Rappel',
    labelAr: 'تذكير',
    tagline: 'Rappel important',
  },
};

// ─── Professional HTML Template ───────────────────────────────────────────────
function buildHtmlEmail(subject, bodyHtml, recipientName, options = {}) {
  const { template = 'announcement', imageUrl = null, ctaText = '', ctaUrl = '', language = 'fr' } = options;
  const tmpl = TEMPLATES[template] || TEMPLATES.announcement;

  const firstName = recipientName
    ? recipientName.split(' ')[0]
    : 'Membre';

  const processedBody = bodyHtml
    .replace(/\{firstname\}/gi, firstName)
    .replace(/\[firstname\]/gi, firstName)
    .replace(/\{name\}/gi, recipientName || 'Membre')
    .replace(/\[name\]/gi, recipientName || 'Membre');

  const isRtl = language === 'ar';
  const dir = isRtl ? 'rtl' : 'ltr';

  const imageBlock = imageUrl ? `
    <tr>
      <td style="padding:0;">
        <img src="${imageUrl}" alt="" style="width:100%;height:auto;display:block;" />
      </td>
    </tr>` : '';

  const ctaBlock = (ctaText && ctaUrl) ? `
    <tr>
      <td style="padding:28px 40px 12px;text-align:center;">
        <a href="${ctaUrl}" target="_blank" style="
          display:inline-block;padding:14px 42px;
          background:${tmpl.accent};color:#ffffff;
          border-radius:8px;text-decoration:none;
          font-weight:700;font-size:15px;letter-spacing:0.3px;
        ">${ctaText}</a>
      </td>
    </tr>` : '';

  const tagLabel = isRtl ? tmpl.labelAr : tmpl.label;

  return `<!DOCTYPE html>
<html lang="${language}" dir="${dir}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:32px 8px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.06);border:1px solid #e4e4e7;">

          <!-- Banner with white background -->
          <tr>
            <td style="background:#ffffff;padding:24px 32px 16px;text-align:center;border-bottom:1px solid #f0f0f0;">
              <img src="${BANNER_URL}" alt="MegaFit" style="max-width:200px;height:auto;display:inline-block;" />
            </td>
          </tr>

          <!-- Category Tag -->
          <tr>
            <td style="background:#ffffff;padding:16px 40px 0;">
              <div style="display:inline-block;padding:5px 14px;border-radius:6px;background:${tmpl.accent}12;border:1px solid ${tmpl.accent}25;font-size:11px;font-weight:700;color:${tmpl.accent};letter-spacing:0.5px;text-transform:uppercase;">
                ${tagLabel}
              </div>
            </td>
          </tr>

          ${imageBlock}

          <!-- Body -->
          <tr>
            <td style="background:#ffffff;padding:20px 40px 32px;color:#27272a;font-size:15px;line-height:1.8;direction:${dir};">
              ${processedBody}
            </td>
          </tr>

          ${ctaBlock}

          <!-- Spacer -->
          <tr><td style="background:#ffffff;height:8px;"></td></tr>

          <!-- Footer -->
          <tr>
            <td style="background:#fafafa;padding:24px 40px;text-align:center;border-top:1px solid #f0f0f0;">
              <div style="font-size:12px;color:#71717a;line-height:1.6;">
                <strong style="color:#52525b;">MegaFit</strong><br>
                Dokkarat &middot; Sa&iuml;ss &middot; Anfa &middot; Casa Lady
              </div>
              <div style="margin-top:12px;font-size:10px;color:#a1a1aa;line-height:1.5;">
                Vous recevez cet email en tant que membre de MegaFit.<br>
                Pour vous d&eacute;sabonner, r&eacute;pondez &laquo; STOP &raquo; &agrave; cet email.
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

// ─── Send Via Brevo HTTP API ──────────────────────────────────────────────────
async function sendViaBrevo({ sender, to, subject, htmlContent, attachment }) {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) throw new Error('BREVO_API_KEY is not configured');

  const body = {
    sender,
    to,
    subject,
    htmlContent
  };
  if (attachment) {
    body.attachment = attachment;
  }

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.message || `Brevo API error: ${res.status}`);
  }
  return data;
}

// ─── Send Single Email ────────────────────────────────────────────────────────
async function sendEmail(to, subject, htmlBody, recipientName, options = {}) {
  const html = buildHtmlEmail(subject, htmlBody, recipientName, options);

  if (process.env.BREVO_API_KEY) {
    const senderEmail = process.env.SMTP_FROM_EMAIL || 'notification@megafit.ma';
    const result = await sendViaBrevo({
      sender: { name: 'MegaFit', email: senderEmail },
      to: [{ email: to, name: recipientName || '' }],
      subject,
      htmlContent: html
    });
    return { messageId: result.messageId, accepted: [to], rejected: [] };
  }

  const transport = getTransporter();
  const info = await transport.sendMail({
    from: SMTP_FROM,
    to,
    subject,
    html,
    headers: {
      'X-Mailer': 'MegaFit Notification System',
      'List-Unsubscribe': `<mailto:${SMTP_FROM_EMAIL}?subject=unsubscribe>`,
    },
  });

  return { messageId: info.messageId, accepted: info.accepted, rejected: info.rejected };
}

// ─── Bulk Sender ──────────────────────────────────────────────────────────────
async function sendBulkEmails(recipients, subject, htmlBody, onProgress, options = {}) {
  if (process.env.BREVO_API_KEY) {
    const senderEmail = process.env.SMTP_FROM_EMAIL || 'notification@megafit.ma';
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

          await sendViaBrevo({
            sender: { name: 'MegaFit', email: senderEmail },
            to: [{ email: r.email, name: r.name || '' }],
            subject: personalSubject,
            htmlContent: html
          });
          sent++;
        } catch (err) {
          failed++;
          errors.push({ email: r.email, error: err.message });
          if (err.message.includes('429') || err.message.includes('timeout') || err.message.includes('limit')) {
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
            'List-Unsubscribe': `<mailto:${SMTP_FROM_EMAIL}?subject=unsubscribe>`,
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
