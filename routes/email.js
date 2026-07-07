// routes/email.js — Send contract PDF by email via cPanel SMTP
// POST /api/send-contract-email
// POST /api/save-member-email

const express = require('express');
const nodemailer = require('nodemailer');

const GYM_LABELS = {
  dokarat: 'Fès Doukkarate',
  marjane: 'Fès Saiss',
  casa1:   'Casa Anfa',
  casa2:   'Casa Lady',
};

// Shared transporter — created once, reused
function createTransporter() {
  const port = parseInt(process.env.SMTP_PORT || '465');
  return nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'mail.megafit.ma',
    port:   port,
    secure: port === 465,                 // SSL on port 465, TLS/STARTTLS on port 587
    auth: {
      user: process.env.SMTP_USER || 'inscription@megafit.ma',
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: false },   // cPanel self-signed certs are fine
  });
}

function emailHtml(firstName, memberName, gymName, contractNumber) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background:#000;padding:28px 32px;text-align:center;">
            <h1 style="color:#a3ff12;margin:0;font-size:30px;letter-spacing:4px;font-weight:900;">MegaFit</h1>
            <p style="color:#94a3b8;margin:6px 0 0;font-size:13px;letter-spacing:1px;">${gymName}</p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="background:#ffffff;padding:36px 32px;">
            <h2 style="color:#1e293b;margin:0 0 20px;font-size:20px;">Bonjour ${firstName} 👋</h2>
            <p style="color:#475569;line-height:1.8;margin:0 0 16px;font-size:15px;">
              Votre inscription à <strong>MegaFit ${gymName}</strong> a bien été confirmée.
            </p>
            <p style="color:#475569;line-height:1.8;margin:0 0 24px;font-size:15px;">
              Veuillez trouver votre <strong>contrat d'adhésion</strong> en pièce jointe (PDF). Conservez-le pour vos archives.
            </p>

            <!-- Info box -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:0;margin-bottom:28px;">
              <tr><td style="padding:18px 20px;">
                <p style="margin:0 0 8px;color:#64748b;font-size:13px;">📄 Contrat N° <strong style="color:#1e293b;">${contractNumber}</strong></p>
                <p style="margin:0;color:#64748b;font-size:13px;">👤 Membre : <strong style="color:#1e293b;">${memberName}</strong></p>
              </td></tr>
            </table>

            <hr style="border:none;border-top:1px solid #f1f5f9;margin:0 0 24px;">

            <p style="color:#94a3b8;font-size:13px;margin:0;text-align:center;line-height:1.7;">
              À bientôt en salle ! 💪<br>
              <strong style="color:#475569;">L'équipe MegaFit ${gymName}</strong>
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f8fafc;padding:16px 32px;text-align:center;border-top:1px solid #e2e8f0;">
            <p style="color:#94a3b8;font-size:11px;margin:0;">
              Cet email a été envoyé automatiquement. Merci de ne pas y répondre directement.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

module.exports = function router(deps = {}) {
  const r  = express.Router();
  const db = deps.db || null;

  // ── POST /api/send-contract-email ───────────────────────────────────────────
  r.post('/api/send-contract-email', express.json({ limit: '25mb' }), async (req, res) => {
    const { to, memberName, gymId, contractNumber, pdfBase64, inscriptionId } = req.body;

    // Basic validation
    if (!to || !pdfBase64) {
      return res.status(400).json({ success: false, reason: 'Email ou PDF manquant' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to.trim())) {
      return res.status(400).json({ success: false, reason: 'Adresse email invalide' });
    }

    const gymName    = GYM_LABELS[gymId] || 'MegaFit';
    const firstName  = (memberName || '').split(' ')[0] || 'Cher membre';
    const safeName   = (memberName || 'membre').replace(/[^a-zA-Z0-9\s]/g, '').replace(/\s+/g, '_');

    try {
      const recipientEmail = to.trim();
      const subject = `Votre contrat MegaFit — ${gymName}`;
      const html = emailHtml(firstName, memberName, gymName, contractNumber || '');
      const filename = `Contrat_${safeName}_${contractNumber || ''}.pdf`;

      if (process.env.BREVO_API_KEY) {
        const senderEmail = process.env.SMTP_FROM_INSCRIPTION || 'inscription@megafit.ma';
        const body = {
          sender: { name: 'MegaFit Inscription', email: senderEmail },
          to: [{ email: recipientEmail, name: memberName || '' }],
          subject: subject,
          htmlContent: html,
          attachment: [
            {
              content: pdfBase64,
              name: filename
            }
          ]
        };

        const res = await fetch('https://api.brevo.com/v3/smtp/email', {
          method: 'POST',
          headers: {
            'accept': 'application/json',
            'api-key': process.env.BREVO_API_KEY,
            'content-type': 'application/json'
          },
          body: JSON.stringify(body)
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || `Brevo API error: ${res.status}`);
        }
      } else {
        const transporter = createTransporter();
        await transporter.sendMail({
          from:    `"MegaFit Inscription" <${process.env.SMTP_FROM_INSCRIPTION || 'inscription@megafit.ma'}>`,
          to:      recipientEmail,
          subject: subject,
          html:    html,
          attachments: [{
            filename:    filename,
            content:     pdfBase64,
            encoding:    'base64',
            contentType: 'application/pdf',
          }],
        });
      }

      console.log(`[email] ✅ Contract sent → ${recipientEmail} | ${memberName} | ${contractNumber}`);

      // Optionally save email to inscription record
      if (inscriptionId && db) {
        try {
          await db.run(
            `UPDATE members SET email = ? WHERE id = (SELECT member_id FROM inscriptions WHERE id = ? LIMIT 1)`,
            [to.trim(), inscriptionId]
          );
        } catch (_) { /* non-blocking */ }
      }

      return res.json({ success: true, sentTo: to.trim() });
    } catch (err) {
      console.error('[email] Send error:', err.code, err.responseCode, err.message);

      let reason = "Erreur d'envoi";
      const code = err.responseCode || err.code || '';
      if ([550, 551, 552, 553, 554].includes(code) || err.code === 'EENVELOPE') {
        reason = 'Adresse email invalide ou inexistante';
      } else if (['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT'].includes(err.code)) {
        reason = 'Serveur email inaccessible — réessayez plus tard';
      } else if (code === 535 || code === 534) {
        reason = "Erreur d'authentification SMTP";
      } else if (err.message) {
        reason = err.message.slice(0, 120);
      }
      return res.status(500).json({ success: false, reason });
    }
  });

  // ── POST /api/save-member-email ─────────────────────────────────────────────
  // Saves email to member record without sending — for member panel use later
  r.post('/api/save-member-email', express.json(), async (req, res) => {
    const { inscriptionId, email } = req.body;
    if (!inscriptionId || !email) return res.status(400).json({ ok: false });
    try {
      if (db) {
        await db.run(
          `UPDATE members SET email = ? WHERE id = (SELECT member_id FROM inscriptions WHERE id = ? LIMIT 1)`,
          [email.trim(), inscriptionId]
        );
      }
      return res.json({ ok: true });
    } catch (err) {
      console.error('[save-member-email]', err.message);
      return res.status(500).json({ ok: false, error: err.message });
    }
  });

  return r;
};
