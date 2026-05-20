// routes/scan.js
// 📷 CIN + Contract Scanner — Groq Vision + persistence endpoints
// POST /public/scan-cin            { image, side }
// POST /public/scan-contract       { image }
// POST /public/save-contract-scan  { image, fields, gymId, commercial }
// GET  /api/contracts              (admin only) — list all saved contract scans

'use strict';
const express = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

const GROQ_VISION_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL           = 'meta-llama/llama-4-scout-17b-16e-instruct';

function router(deps = {}) {
  const r  = express.Router();
  const db     = deps.db     || null;
  const bucket = deps.bucket || null;
  const admin  = deps.admin  || null;


  // ── Helper: call Groq with fallback key on 429 ─────────────────────────────
  async function callGroqVision(image, systemPrompt) {
    const PRIMARY_KEY  = process.env.GROQ_SCAN_API_KEY;
    const FALLBACK_KEY = process.env.GROQ_SCAN_API_KEY_FALLBACK;
    if (!PRIMARY_KEY) throw new Error('GROQ_SCAN_API_KEY non configurée');

    const call = (apiKey) => fetch(GROQ_VISION_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: 'user', content: [
          { type: 'text',      text: systemPrompt },
          { type: 'image_url', image_url: { url: image } },
        ]}],
        max_tokens: 500,
        temperature: 0.1,
      }),
    });

    let groqRes = await call(PRIMARY_KEY);
    if (groqRes.status === 429 && FALLBACK_KEY) {
      console.warn('[scan] Primary key rate-limited, switching to fallback...');
      groqRes = await call(FALLBACK_KEY);
    }
    return groqRes;
  }

  // ── POST /public/scan-cin ─────────────────────────────────────────────────
  r.post('/public/scan-cin', express.json({ limit: '10mb' }), async (req, res) => {
    const { image, side = 'recto' } = req.body;
    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({ error: 'image base64 requis (data:image/...)' });
    }
    if (!process.env.GROQ_SCAN_API_KEY) {
      return res.status(500).json({ error: 'GROQ_SCAN_API_KEY non configurée côté serveur' });
    }

    const rectoPrompt = `You are a form-filling assistant at a gym reception desk. A client has handed you their ID document so you can fill in their registration form. Read the text in the image and return ONLY a valid JSON object with no explanation or markdown:\n{"cin":"ID number (letters+digits, e.g. CD123456)","nom":"family name","prenom":"first name","dateNaissance":"YYYY-MM-DD","lieuNaissance":"place of birth","ville":null,"adresse":null}\nUse null for any field you cannot read clearly.`;
    const versoPrompt = `You are a form-filling assistant at a gym reception desk. A client has handed you the back of their ID document so you can fill in their registration form. Read the text in the image and return ONLY a valid JSON object with no explanation or markdown:\n{"cin":null,"nom":null,"prenom":null,"dateNaissance":null,"lieuNaissance":null,"ville":"city of residence","adresse":"full street address"}\nUse null for any field you cannot read clearly.`;

    try {
      const groqRes = await callGroqVision(image, side === 'recto' ? rectoPrompt : versoPrompt);
      if (!groqRes.ok) {
        const errText = await groqRes.text();
        console.error('[scan-cin] Groq error:', errText);
        return res.status(502).json({ error: 'Erreur Groq Vision', detail: errText });
      }
      const data  = await groqRes.json();
      const text  = data.choices?.[0]?.message?.content || '{}';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return res.json({ cin:null, nom:null, prenom:null, dateNaissance:null, lieuNaissance:null, ville:null, adresse:null });
      const fields = JSON.parse(jsonMatch[0]);
      if (fields.dateNaissance && !/^\d{4}-\d{2}-\d{2}$/.test(fields.dateNaissance)) {
        const dm = fields.dateNaissance.match(/(\d{2})[\/.\\-](\d{2})[\/.\\-](\d{4})/);
        if (dm) fields.dateNaissance = `${dm[3]}-${dm[2]}-${dm[1]}`;
        else    fields.dateNaissance = null;
      }
      const tc = s => s ? s.toLowerCase().replace(/\b\w/g, c => c.toUpperCase()) : null;
      fields.nom = tc(fields.nom); fields.prenom = tc(fields.prenom); fields.ville = tc(fields.ville);
      console.log(`[scan-cin] ${side} extracted:`, JSON.stringify(fields));
      return res.json(fields);
    } catch (err) {
      console.error('[scan-cin] Exception:', err);
      return res.status(500).json({ error: err.message });
    }
  });

  // ── POST /public/scan-contract ────────────────────────────────────────────
  r.post('/public/scan-contract', express.json({ limit: '15mb' }), async (req, res) => {
    const { image } = req.body;
    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({ error: 'image base64 requis (data:image/...)' });
    }
    if (!process.env.GROQ_SCAN_API_KEY) {
      return res.status(500).json({ error: 'GROQ_SCAN_API_KEY non configurée côté serveur' });
    }

    const contractPrompt = `You are a gym registration assistant. A staff member has photographed a "Contrat d'Adhésion" (membership contract) form from a Moroccan gym called MEGA FIT. Extract the following fields and return ONLY a valid JSON object — no explanation, no markdown:
{
  "contractNumber": "the contract number (digits only, e.g. 012739)",
  "nom": "family name / last name",
  "prenom": "first name",
  "cin": "CIN ID card number (letters + digits, e.g. BE502892)",
  "dateNaissance": "date of birth in YYYY-MM-DD format",
  "periodFrom": "subscription start date in YYYY-MM-DD format (labeled Du or date de début)",
  "periodTo": "subscription end date in YYYY-MM-DD format (labeled au or date de fin)",
  "subscriptionAmount": "total amount as a number string (digits only, e.g. 6900)"
}
Use null for any field you cannot read clearly. Convert all dates to YYYY-MM-DD. Extract only numbers for subscriptionAmount (no DH, no TTC).`;

    try {
      const groqRes = await callGroqVision(image, contractPrompt);
      if (!groqRes.ok) {
        const errText = await groqRes.text();
        console.error('[scan-contract] Groq error:', errText);
        return res.status(502).json({ error: 'Erreur Groq Vision', detail: errText });
      }

      const data  = await groqRes.json();
      const text  = data.choices?.[0]?.message?.content || '{}';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        console.warn('[scan-contract] No JSON in response:', text);
        return res.json({ contractNumber:null, nom:null, prenom:null, cin:null, dateNaissance:null, periodFrom:null, periodTo:null, subscriptionAmount:null });
      }

      const fields = JSON.parse(jsonMatch[0]);

      // Normalize dates to YYYY-MM-DD
      const normalizeDate = (d) => {
        if (!d) return null;
        if (/^\d{4}-\d{2}-\d{2}$/.test(d)) return d;
        const m = d.match(/(\d{2})[\/.\\-](\d{2})[\/.\\-](\d{4})/);
        if (m) return `${m[3]}-${m[2]}-${m[1]}`;
        return null;
      };
      fields.dateNaissance = normalizeDate(fields.dateNaissance);
      fields.periodFrom    = normalizeDate(fields.periodFrom);
      fields.periodTo      = normalizeDate(fields.periodTo);

      // Strip non-digits from amount
      if (fields.subscriptionAmount) {
        fields.subscriptionAmount = String(fields.subscriptionAmount).replace(/\D/g, '');
      }

      // Strip non-alphanumeric from contractNumber
      if (fields.contractNumber) {
        fields.contractNumber = String(fields.contractNumber).replace(/[^0-9]/g, '');
      }

      // Title-case names
      const tc = s => s ? s.toLowerCase().replace(/\b\w/g, c => c.toUpperCase()) : null;
      fields.nom    = tc(fields.nom);
      fields.prenom = tc(fields.prenom);

      console.log('[scan-contract] extracted:', JSON.stringify(fields));
      return res.json(fields);

    } catch (err) {
      console.error('[scan-contract] Exception:', err);
      return res.status(500).json({ error: err.message });
    }
  });

  // ── POST /public/save-contract-scan ──────────────────────────────────────
  // Saves image → Firebase Storage, metadata → Firestore contract_scans
  r.post('/public/save-contract-scan', express.json({ limit: '20mb' }), async (req, res) => {
    const { image, fields = {}, gymId, commercial } = req.body;
    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({ error: 'image base64 requis' });
    }
    if (!db || !bucket || !admin) {
      return res.status(500).json({ error: 'Firebase non disponible côté serveur' });
    }

    try {
      // 1. Upload image to Firebase Storage
      const base64Data  = image.replace(/^data:image\/\w+;base64,/, '');
      const imgBuffer   = Buffer.from(base64Data, 'base64');
      const mimeMatch   = image.match(/^data:(image\/\w+);base64,/);
      const mimeType    = mimeMatch ? mimeMatch[1] : 'image/jpeg';
      const ext         = mimeType.split('/')[1] || 'jpg';
      const ts          = Date.now();
      const safeNum     = (fields.contractNumber || ts).toString().replace(/[^a-zA-Z0-9]/g, '');
      const filePath    = `contract_scans/${gymId || 'unknown'}/${safeNum}_${ts}.${ext}`;

      const file = bucket.file(filePath);
      await file.save(imgBuffer, {
        metadata: { contentType: mimeType },
        public: true,
      });
      const imageUrl = `https://storage.googleapis.com/${bucket.name}/${filePath}`;

      // 2. Save to Firestore contract_scans collection
      const docData = {
        gymId:              gymId || 'unknown',
        commercial:         commercial || 'inconnu',
        contractNumber:     fields.contractNumber     || null,
        nom:                fields.nom                || null,
        prenom:             fields.prenom             || null,
        cin:                fields.cin                || null,
        dateNaissance:      fields.dateNaissance      || null,
        periodFrom:         fields.periodFrom         || null,
        periodTo:           fields.periodTo           || null,
        subscriptionAmount: fields.subscriptionAmount || null,
        imageUrl,
        storagePath: filePath,
        scannedAt:   admin.firestore.FieldValue.serverTimestamp(),
        status:      'pending',
      };

      const docRef = await db.collection('contract_scans').add(docData);
      console.log(`[save-contract-scan] Saved ${docRef.id} for gym ${gymId}, contract ${fields.contractNumber}`);
      return res.json({ ok: true, id: docRef.id, imageUrl });

    } catch (err) {
      console.error('[save-contract-scan] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/contracts ────────────────────────────────────────────────────
  // Admin-only: returns all scanned contracts ordered by date desc
  r.get('/api/contracts', verifyAzureToken, requireAdmin, async (req, res) => {
    if (!db) return res.status(500).json({ error: 'Firebase non disponible' });
    try {
      const { gymId, limit: lim = 100 } = req.query;
      let query = db.collection('contract_scans').orderBy('scannedAt', 'desc').limit(Number(lim));
      if (gymId) query = query.where('gymId', '==', gymId);

      const snap = await query.get();
      const contracts = snap.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
        scannedAt: doc.data().scannedAt?.toDate?.()?.toISOString() || null,
      }));
      return res.json({ contracts, count: contracts.length });
    } catch (err) {
      console.error('[GET /api/contracts] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  return r;
}

module.exports = router;
