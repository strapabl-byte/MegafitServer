// routes/scan.js
// 📷 CIN + Contract Scanner — Smart Multi-Crop GPT-4o Vision
//
// POST /public/scan-cin            { image, side }          → Groq Llama 4 Scout (fast ID OCR)
// POST /public/scan-contract       { image, mode? }         → GPT-4o Vision, 6 crops, rich schema
// POST /public/save-contract-scan  { image, fields, gymId, commercial }
// GET  /api/contracts              (admin only) — list saved contract scans
// PATCH /api/contracts/:id         (admin only) — update fields / status

'use strict';
const express = require('express');
const sharp   = require('sharp');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

// ── Model config ──────────────────────────────────────────────────────────────
const GROQ_VISION_URL  = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_CIN_MODEL   = 'meta-llama/llama-4-scout-17b-16e-instruct';
const OPENAI_URL       = 'https://api.openai.com/v1/chat/completions';
const OPENAI_SMART     = 'gpt-5.5';         // Smart Scan — best accuracy, handwriting
const OPENAI_FAST      = 'gpt-5.5-instant'; // Quick Scan — fast + cost-effective

// ── Image preprocessing with sharp ───────────────────────────────────────────
/**
 * Takes a base64 data-URI, returns an object with:
 *   { full, topLeft, topRight, midLeft, midRight, bottom }
 * Each value is a base64 JPEG data-URI ready to send to OpenAI.
 */
async function preprocessAndCrop(base64DataUri) {
  // Strip the data: prefix
  const match = base64DataUri.match(/^data:(image\/\w+);base64,(.+)$/);
  if (!match) throw new Error('Format image invalide (attendu: data:image/...;base64,...)');
  const inputBuffer = Buffer.from(match[2], 'base64');

  // 1. Decode + auto-rotate EXIF + normalise to JPEG
  const raw = sharp(inputBuffer).rotate(); // auto-rotate from EXIF

  // 2. Get metadata to know original dimensions
  const meta = await raw.clone().metadata();
  const origW = meta.width  || 1200;
  const origH = meta.height || 1700;

  // 3. Resize to at least 2000px wide (upscale if needed), maintain aspect
  const targetW = Math.max(origW, 2000);
  const targetH = Math.round((targetW / origW) * origH);

  // 4. Enhance: normalise contrast, moderate sharpening
  const enhanced = raw.clone()
    .resize(targetW, targetH, { fit: 'fill' })
    .normalise()
    .sharpen({ sigma: 1.0, m1: 0.5, m2: 2.0 })
    .jpeg({ quality: 92 });

  const fullBuf = await enhanced.toBuffer();
  const fullB64 = `data:image/jpeg;base64,${fullBuf.toString('base64')}`;

  // 5. Generate 5 crops (relative to targetW × targetH)
  //   top-left   : member identity (nom, prénom, CIN, naissance)
  //   top-right  : phone / address / contact
  //   mid-left   : subscription dates + price
  //   mid-right  : options + payment method
  //   bottom     : access type / signature / date

  // Use a shared enhanced base buffer for cropping
  const base = sharp(fullBuf);

  const cropToB64 = async (left, top, width, height) => {
    const w = Math.min(width,  targetW - left);
    const h = Math.min(height, targetH - top);
    if (w <= 0 || h <= 0) return fullB64; // safety fallback
    const buf = await base.clone()
      .extract({ left, top, width: w, height: h })
      .normalise()
      .sharpen({ sigma: 1.2, m1: 0.6, m2: 2.5 })
      .jpeg({ quality: 94 })
      .toBuffer();
    return `data:image/jpeg;base64,${buf.toString('base64')}`;
  };

  const halfW  = Math.floor(targetW / 2);
  const thirdH = Math.floor(targetH / 3);

  const [topLeft, topRight, midLeft, midRight, bottom] = await Promise.all([
    cropToB64(0,             0,               halfW,  thirdH),
    cropToB64(halfW,         0,               halfW,  thirdH),
    cropToB64(0,             thirdH,          halfW,  thirdH),
    cropToB64(halfW,         thirdH,          halfW,  thirdH),
    cropToB64(0,             thirdH * 2,      targetW, thirdH + (targetH - thirdH * 3)),
  ]);

  return { full: fullB64, topLeft, topRight, midLeft, midRight, bottom };
}

// ── Convert base64 data-URI → OpenAI image_url content block ─────────────────
function toImageBlock(base64DataUri, detail = 'high') {
  return { type: 'image_url', image_url: { url: base64DataUri, detail } };
}

// ── Groq Vision call (CIN scanner) ───────────────────────────────────────────
async function callGroqVision(image, systemPrompt) {
  const PRIMARY_KEY  = process.env.GROQ_SCAN_API_KEY;
  const FALLBACK_KEY = process.env.GROQ_SCAN_API_KEY_FALLBACK;
  if (!PRIMARY_KEY) throw new Error('GROQ_SCAN_API_KEY non configurée');

  const call = (apiKey) => fetch(GROQ_VISION_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: GROQ_CIN_MODEL,
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
    console.warn('[scan-cin] Primary Groq key rate-limited, switching to fallback...');
    groqRes = await call(FALLBACK_KEY);
  }
  return groqRes;
}

// ── OpenAI Vision call — multi-image (contract scanner) ─────────────────────
async function callOpenAIMultiImage(crops, systemPrompt, model = OPENAI_SMART) {
  const OPENAI_KEY = process.env.OPENAI_API_KEY;
  if (!OPENAI_KEY) throw new Error('OPENAI_API_KEY non configurée. Ajoutez-la dans les variables d\'environnement Render.');

  const detail = model === OPENAI_SMART ? 'high' : 'high';

  const imageBlocks = [
    toImageBlock(crops.full,     detail),
    toImageBlock(crops.topLeft,  detail),
    toImageBlock(crops.topRight, detail),
    toImageBlock(crops.midLeft,  detail),
    toImageBlock(crops.midRight, detail),
    toImageBlock(crops.bottom,   detail),
  ];

  const res = await fetch(OPENAI_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${OPENAI_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
        {
          role: 'system',
          content: systemPrompt,
        },
        {
          role: 'user',
          content: [
            {
              type: 'text',
              text: 'Voici le contrat complet (image 1) suivi de 5 sections recadrées (images 2–6). Extrais toutes les données visibles dans le JSON demandé.',
            },
            ...imageBlocks,
          ],
        },
      ],
      max_tokens: 2000,
      temperature: 0.05,
      response_format: { type: 'json_object' },
    }),
  });
  return res;
}

// ── Groq fallback (single image) for contract when no OpenAI key ─────────────
async function callGroqContractFallback(crops, contractPrompt) {
  const PRIMARY_KEY  = process.env.GROQ_SCAN_API_KEY;
  const FALLBACK_KEY = process.env.GROQ_SCAN_API_KEY_FALLBACK;
  if (!PRIMARY_KEY) throw new Error('Ni OPENAI_API_KEY ni GROQ_SCAN_API_KEY configurées');

  const call = (apiKey) => fetch(GROQ_VISION_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: GROQ_CIN_MODEL,
      messages: [{ role: 'user', content: [
        { type: 'text', text: contractPrompt },
        { type: 'image_url', image_url: { url: crops.full } },
      ]}],
      max_tokens: 1200,
      temperature: 0.1,
    }),
  });

  let res = await call(PRIMARY_KEY);
  if (res.status === 429 && FALLBACK_KEY) {
    console.warn('[scan-contract] Groq primary rate-limited, fallback...');
    res = await call(FALLBACK_KEY);
  }
  return res;
}

// ── Build a field node with defaults ─────────────────────────────────────────
function field(value = null, confidence = 0, raw = '', needsReview = false) {
  return { value, confidence, raw, needsReview };
}

// ── Business validation pass ──────────────────────────────────────────────────
function validateContract(data) {
  const warnings = [];

  // Phone format
  const phone = data.member?.phone?.value;
  if (phone && !/^0[5-7]\d{8}$/.test(phone.replace(/[\s.-]/g, ''))) {
    warnings.push('Format numéro de téléphone incorrect (attendu: 0X XXXXXXXX)');
    if (data.member.phone) data.member.phone.needsReview = true;
  }

  // CIN format
  const cin = data.member?.cin?.value;
  if (cin && !/^[A-Z]{1,2}[0-9]{4,8}$/i.test(cin.replace(/\s/g, ''))) {
    warnings.push('Format CIN inhabituel (ex: BE502892)');
    if (data.member.cin) data.member.cin.needsReview = true;
  }

  // Payment total vs breakdown
  const total =
    (Number(data.payment?.cashAmountDhs?.value)     || 0) +
    (Number(data.payment?.cardAmountDhs?.value)      || 0) +
    (Number(data.payment?.chequeAmountDhs?.value)    || 0) +
    (Number(data.payment?.transferAmountDhs?.value)  || 0) +
    (Number(data.payment?.remainingAmountDhs?.value) || 0);
  const contractTotal = Number(data.subscription?.totalAmountDhs?.value) || 0;
  if (contractTotal > 0 && total > 0 && Math.abs(total - contractTotal) > 10) {
    warnings.push(`Total contrat (${contractTotal} DH) ≠ somme des paiements (${total} DH)`);
    if (data.payment?.remainingAmountDhs) data.payment.remainingAmountDhs.needsReview = true;
  }

  // Date order
  const start = data.subscription?.startDate?.value;
  const end   = data.subscription?.endDate?.value;
  if (start && end) {
    const s = new Date(start), e = new Date(end);
    if (!isNaN(s) && !isNaN(e) && e <= s) {
      warnings.push('Date de fin antérieure ou égale à la date de début');
      if (data.subscription.endDate) data.subscription.endDate.needsReview = true;
    }
  }

  // Overall confidence
  const confidences = [];
  function collectConfidences(obj) {
    if (!obj || typeof obj !== 'object') return;
    if ('confidence' in obj) { confidences.push(obj.confidence); return; }
    Object.values(obj).forEach(collectConfidences);
  }
  collectConfidences(data);
  const avg = confidences.length ? confidences.reduce((a, b) => a + b, 0) / confidences.length : 0;
  data.review.overallConfidence = parseFloat(avg.toFixed(2));

  // Collect fields needing review
  const needing = [];
  function collectReviewFields(obj, prefix = '') {
    if (!obj || typeof obj !== 'object') return;
    if ('needsReview' in obj) { if (obj.needsReview && obj.value !== null && obj.value !== '') needing.push(prefix); return; }
    Object.entries(obj).forEach(([k, v]) => collectReviewFields(v, prefix ? `${prefix}.${k}` : k));
  }
  collectReviewFields(data);
  data.review.fieldsNeedingReview = needing;
  data.review.warnings = warnings;

  return warnings;
}

// ── Build empty schema ────────────────────────────────────────────────────────
function buildEmptySchema() {
  return {
    documentType: 'gym_membership_contract',
    contract: {
      club:           field(), commercial: field(), contractNumber: field(), isRenewal: field(false),
    },
    member: {
      civility: field(), lastName: field(), firstName: field(), cin: field(),
      birthDate: field(), address: field(), postalCode: field(), city: field(),
      phone: field(), email: field(), emergencyContactName: field(), emergencyPhone: field(),
    },
    subscription: {
      durationDays: field(null), durationWeeks: field(null), durationMonths: field(null), durationYears: field(null),
      startDate: field(), endDate: field(), totalAmountDhs: field(null),
    },
    options: {
      withTransfer: field(false), withoutTransfer: field(false), privateCoaching: field(false),
      insurance: field(false), covidInsurance: field(false),
    },
    payment: {
      paymentMethod: field(), cashAmountDhs: field(null), cardAmountDhs: field(null),
      chequeAmountDhs: field(null), transferAmountDhs: field(null), remainingAmountDhs: field(null),
    },
    access:    { local: field(false), multiclub: field(false) },
    signature: { city: field(), date: field(), memberSigned: field(false), staffSigned: field(false) },
    review:    { overallConfidence: 0, fieldsNeedingReview: [], warnings: [] },
  };
}

// ── Parse / normalise the raw AI response into the schema ────────────────────
function normaliseExtracted(raw) {
  const out = buildEmptySchema();

  function applyField(target, key, src) {
    if (!src || typeof src !== 'object') return;
    const val  = src.value  !== undefined ? src.value  : null;
    const conf = typeof src.confidence === 'number' ? Math.min(1, Math.max(0, src.confidence)) : 0.5;
    const rawT = src.raw   !== undefined ? String(src.raw) : '';
    const review = !!src.needsReview;
    if (target[key] !== undefined) {
      target[key] = field(val, conf, rawT, review);
    }
  }

  function applySection(target, src) {
    if (!src || typeof src !== 'object') return;
    Object.keys(target).forEach(k => applyField(target, k, src[k]));
  }

  applySection(out.contract,     raw.contract);
  applySection(out.member,       raw.member);
  applySection(out.subscription, raw.subscription);
  applySection(out.options,      raw.options);
  applySection(out.payment,      raw.payment);
  applySection(out.access,       raw.access);
  applySection(out.signature,    raw.signature);

  // Normalise dates
  const nd = (v) => {
    if (!v) return null;
    if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return v;
    const m = v.match(/(\d{2})[/.\-\\](\d{2})[/.\-\\](\d{4})/);
    if (m) return `${m[3]}-${m[2]}-${m[1]}`;
    return v;
  };
  ['birthDate'].forEach(k => { if (out.member[k]?.value) out.member[k].value = nd(out.member[k].value); });
  ['startDate','endDate'].forEach(k => { if (out.subscription[k]?.value) out.subscription[k].value = nd(out.subscription[k].value); });
  if (out.signature.date?.value) out.signature.date.value = nd(out.signature.date.value);

  // Normalise phone (10 digits)
  if (out.member.phone?.value) {
    const p = String(out.member.phone.value).replace(/[\s.\-]/g, '');
    if (/^[0-9]{10}$/.test(p)) out.member.phone.value = p;
  }

  // Title-case names
  const tc = s => s ? s.toLowerCase().replace(/\b\w/g, c => c.toUpperCase()) : null;
  if (out.member.lastName?.value)  out.member.lastName.value  = tc(out.member.lastName.value);
  if (out.member.firstName?.value) out.member.firstName.value = tc(out.member.firstName.value);

  // Strip non-digit from amounts
  ['cashAmountDhs','cardAmountDhs','chequeAmountDhs','transferAmountDhs','remainingAmountDhs'].forEach(k => {
    const v = out.payment[k]?.value;
    if (v !== null && v !== undefined) {
      const n = parseFloat(String(v).replace(/[^\d.]/g, ''));
      out.payment[k].value = isNaN(n) ? null : n;
    }
  });
  if (out.subscription.totalAmountDhs?.value !== null) {
    const n = parseFloat(String(out.subscription.totalAmountDhs.value).replace(/[^\d.]/g, ''));
    out.subscription.totalAmountDhs.value = isNaN(n) ? null : n;
  }

  // Contract number — digits only
  if (out.contract.contractNumber?.value) {
    out.contract.contractNumber.value = String(out.contract.contractNumber.value).replace(/\D/g, '') || null;
  }

  return out;
}

// ── Flatten rich schema → legacy flat fields (for backward compat with inscription form) ──
function flattenToLegacy(rich) {
  return {
    contractNumber:     rich.contract?.contractNumber?.value     || '',
    nom:                rich.member?.lastName?.value             || '',
    prenom:             rich.member?.firstName?.value            || '',
    cin:                rich.member?.cin?.value                  || '',
    dateNaissance:      rich.member?.birthDate?.value            || '',
    periodFrom:         rich.subscription?.startDate?.value      || '',
    periodTo:           rich.subscription?.endDate?.value        || '',
    subscriptionAmount: rich.subscription?.totalAmountDhs?.value?.toString() || '',
    phone:              rich.member?.phone?.value                || '',
    ville:              rich.member?.city?.value                 || '',
    adresse:            rich.member?.address?.value              || '',
  };
}

// ── System prompt for contract extraction ────────────────────────────────────
const CONTRACT_SYSTEM_PROMPT = `
You are a high-accuracy document extraction engine specialised in Moroccan gym membership contracts (Contrat d'Adhésion — MEGA FIT).

You receive 6 images:
1. Full contract page
2. Top-left crop  — member identity (nom, prénom, CIN, date naissance, adresse, ville)
3. Top-right crop — phone, contact urgence, email
4. Middle-left crop — dates d'abonnement, durée, montant
5. Middle-right crop — options (coaching privé, assurance, transfert), mode de paiement
6. Bottom crop — accès local/multiclub, signature, date, visa

Rules:
- Extract ONLY what is visibly written or printed. Never invent.
- For each field return: value, confidence (0.0–1.0), raw (exact handwritten text), needsReview (true if uncertain).
- If a field is blank or illegible, return value: null, confidence: 0.0, needsReview: false.
- For handwriting you can partially read, set confidence < 0.75 and needsReview: true.
- Normalize dates to YYYY-MM-DD. Accept DD/MM/YYYY, DD.MM.YYYY, DD-MM-YYYY as input.
- Normalize Moroccan phone numbers to 10 digits (no spaces, no dots, no dashes).
- Amounts are in Moroccan Dirhams (DH / MAD). Return as numbers.
- Checked boxes: look for ✓, X, or filled boxes. Return boolean true/false.
- Compare subscription total with payment breakdown — flag discrepancies.
- Return ONLY valid JSON matching the exact schema. No markdown, no explanation.

Required JSON schema (return ALL fields, even if null):
{
  "documentType": "gym_membership_contract",
  "contract": {
    "club":           { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "commercial":     { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "contractNumber": { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "isRenewal":      { "value": boolean,     "confidence": number, "raw": string, "needsReview": boolean }
  },
  "member": {
    "civility":             { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "lastName":             { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "firstName":            { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "cin":                  { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "birthDate":            { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "address":              { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "postalCode":           { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "city":                 { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "phone":                { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "email":                { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "emergencyContactName": { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "emergencyPhone":       { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean }
  },
  "subscription": {
    "durationDays":    { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "durationWeeks":   { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "durationMonths":  { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "durationYears":   { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "startDate":       { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "endDate":         { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "totalAmountDhs":  { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean }
  },
  "options": {
    "withTransfer":    { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean },
    "withoutTransfer": { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean },
    "privateCoaching": { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean },
    "insurance":       { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean },
    "covidInsurance":  { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean }
  },
  "payment": {
    "paymentMethod":       { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "cashAmountDhs":       { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "cardAmountDhs":       { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "chequeAmountDhs":     { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "transferAmountDhs":   { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean },
    "remainingAmountDhs":  { "value": number|null, "confidence": number, "raw": string, "needsReview": boolean }
  },
  "access": {
    "local":     { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean },
    "multiclub": { "value": boolean, "confidence": number, "raw": string, "needsReview": boolean }
  },
  "signature": {
    "city":         { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "date":         { "value": string|null, "confidence": number, "raw": string, "needsReview": boolean },
    "memberSigned": { "value": boolean,     "confidence": number, "raw": string, "needsReview": boolean },
    "staffSigned":  { "value": boolean,     "confidence": number, "raw": string, "needsReview": boolean }
  }
}
`.trim();

// ═══════════════════════════════════════════════════════════════════════════════
// Router factory
// ═══════════════════════════════════════════════════════════════════════════════
function router(deps = {}) {
  const r      = express.Router();
  const db     = deps.db     || null;
  const bucket = deps.bucket || null;
  const admin  = deps.admin  || null;

  // ── POST /public/scan-cin ─────────────────────────────────────────────────
  // CIN scanner — uses Groq Vision (fast + cheap for flat text IDs)
  r.post('/public/scan-cin', express.json({ limit: '10mb' }), async (req, res) => {
    const { image, side = 'recto' } = req.body;
    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({ error: 'image base64 requis (data:image/...)' });
    }
    if (!process.env.GROQ_SCAN_API_KEY) {
      return res.status(500).json({ error: 'GROQ_SCAN_API_KEY non configurée' });
    }

    const rectoPrompt = `You are a form-filling assistant at a gym. Read this Moroccan ID card (CIN) recto and return ONLY valid JSON — no explanation, no markdown:\n{"cin":"ID number (letters+digits, e.g. CD123456)","nom":"family name","prenom":"first name","dateNaissance":"YYYY-MM-DD","lieuNaissance":"place of birth","ville":null,"adresse":null}\nUse null for fields you cannot read.`;
    const versoPrompt = `You are a form-filling assistant at a gym. Read the back of this Moroccan ID card and return ONLY valid JSON — no explanation, no markdown:\n{"cin":null,"nom":null,"prenom":null,"dateNaissance":null,"lieuNaissance":null,"ville":"city of residence","adresse":"full street address"}\nUse null for fields you cannot read.`;

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
      // Normalize date
      if (fields.dateNaissance && !/^\d{4}-\d{2}-\d{2}$/.test(fields.dateNaissance)) {
        const dm = fields.dateNaissance.match(/(\d{2})[/.\-\\](\d{2})[/.\-\\](\d{4})/);
        if (dm) fields.dateNaissance = `${dm[3]}-${dm[2]}-${dm[1]}`;
        else    fields.dateNaissance = null;
      }
      const tc = s => s ? s.toLowerCase().replace(/\b\w/g, c => c.toUpperCase()) : null;
      fields.nom = tc(fields.nom); fields.prenom = tc(fields.prenom); fields.ville = tc(fields.ville);
      console.log(`[scan-cin] ${side} → ${JSON.stringify(fields)}`);
      return res.json(fields);
    } catch (err) {
      console.error('[scan-cin] Exception:', err);
      return res.status(500).json({ error: err.message });
    }
  });

  // ── POST /public/scan-contract ─────────────────────────────────────────────
  // Smart multi-crop GPT-4o contract scanner
  // Body: { image: base64DataUri, mode?: 'smart'|'fast' }
  // Returns: { rich: <full schema>, legacy: <flat fields for form>, model, crops }
  r.post('/public/scan-contract', express.json({ limit: '20mb' }), async (req, res) => {
    const { image, mode = 'smart' } = req.body;
    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({ error: 'image base64 requis (data:image/...)' });
    }

    const useOpenAI = !!process.env.OPENAI_API_KEY;
    const model     = useOpenAI ? (mode === 'fast' ? OPENAI_FAST : OPENAI_SMART) : null;

    console.log(`[scan-contract] mode=${mode}, useOpenAI=${useOpenAI}, model=${model || 'groq-fallback'}`);

    try {
      // ── Step 1: Preprocess + generate 6 images ──────────────────────────────
      console.log('[scan-contract] Preprocessing image + generating crops...');
      const crops = await preprocessAndCrop(image);
      console.log(`[scan-contract] Crops ready. Full size: ${crops.full.length} chars`);

      // ── Step 2: Call vision model ───────────────────────────────────────────
      let scanRes;
      if (useOpenAI) {
        scanRes = await callOpenAIMultiImage(crops, CONTRACT_SYSTEM_PROMPT, model);
      } else {
        // Fallback: Groq with full image only
        console.warn('[scan-contract] No OPENAI_API_KEY — using Groq fallback (single image, less accurate)');
        scanRes = await callGroqContractFallback(crops, CONTRACT_SYSTEM_PROMPT);
      }

      if (!scanRes.ok) {
        const errText = await scanRes.text();
        console.error('[scan-contract] Vision error:', errText);
        return res.status(502).json({ error: 'Erreur Vision API', detail: errText });
      }

      const data = await scanRes.json();
      const rawText = data.choices?.[0]?.message?.content || '{}';
      console.log('[scan-contract] Raw AI response length:', rawText.length);

      // ── Step 3: Parse and normalise into schema ─────────────────────────────
      let parsed;
      try {
        const jsonMatch = rawText.match(/\{[\s\S]*\}/);
        if (!jsonMatch) throw new Error('No JSON in AI response');
        parsed = JSON.parse(jsonMatch[0]);
      } catch (parseErr) {
        console.error('[scan-contract] JSON parse error:', parseErr.message, '\nRaw:', rawText.slice(0, 500));
        // Return empty schema rather than crashing
        parsed = {};
      }

      const rich = normaliseExtracted(parsed);

      // ── Step 4: Business validation pass ────────────────────────────────────
      const warnings = validateContract(rich);
      if (warnings.length) console.log('[scan-contract] Validation warnings:', warnings);

      // ── Step 5: Return both rich + legacy flat ───────────────────────────────
      const legacy = flattenToLegacy(rich);
      console.log(`[scan-contract] Done. Overall confidence: ${rich.review.overallConfidence}, fieldsNeedingReview: ${rich.review.fieldsNeedingReview.length}`);

      return res.json({
        rich,
        legacy,
        model: model || 'groq-fallback',
        useOpenAI,
        cropsGenerated: 6,
      });

    } catch (err) {
      console.error('[scan-contract] Exception:', err);
      return res.status(500).json({ error: err.message });
    }
  });

  // ── POST /public/save-contract-scan ──────────────────────────────────────
  // Saves image → Firebase Storage, rich schema → Firestore contract_scans
  r.post('/public/save-contract-scan', express.json({ limit: '25mb' }), async (req, res) => {
    const { image, rich, fields = {}, gymId, commercial } = req.body;
    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({ error: 'image base64 requis' });
    }
    if (!db || !bucket || !admin) {
      return res.status(500).json({ error: 'Firebase non disponible côté serveur' });
    }

    try {
      // Upload original image to Firebase Storage
      const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
      const imgBuffer  = Buffer.from(base64Data, 'base64');
      const mimeMatch  = image.match(/^data:(image\/\w+);base64,/);
      const mimeType   = mimeMatch ? mimeMatch[1] : 'image/jpeg';
      const ext        = mimeType.split('/')[1] || 'jpg';
      const ts         = Date.now();

      // Use contractNumber from rich schema or legacy fields
      const contractNum = rich?.contract?.contractNumber?.value || fields?.contractNumber || ts;
      const safeNum     = String(contractNum).replace(/[^a-zA-Z0-9]/g, '');
      const filePath    = `contract_scans/${gymId || 'unknown'}/${safeNum}_${ts}.${ext}`;

      const file = bucket.file(filePath);
      await file.save(imgBuffer, { metadata: { contentType: mimeType }, public: true });
      const imageUrl = `https://storage.googleapis.com/${bucket.name}/${filePath}`;

      // Legacy flat fields (for backward compat)
      const legacy = rich ? flattenToLegacy(rich) : fields;

      // Save to Firestore — store both legacy + rich schema
      const docData = {
        gymId:              gymId        || 'unknown',
        commercial:         commercial   || 'inconnu',
        // Legacy flat fields
        contractNumber:     legacy.contractNumber     || null,
        nom:                legacy.nom                || null,
        prenom:             legacy.prenom             || null,
        cin:                legacy.cin                || null,
        dateNaissance:      legacy.dateNaissance      || null,
        periodFrom:         legacy.periodFrom         || null,
        periodTo:           legacy.periodTo           || null,
        subscriptionAmount: legacy.subscriptionAmount || null,
        phone:              legacy.phone              || null,
        ville:              legacy.ville              || null,
        // Rich schema (full AI extraction with confidence)
        richExtraction:     rich || null,
        overallConfidence:  rich?.review?.overallConfidence || null,
        fieldsNeedingReview: rich?.review?.fieldsNeedingReview || [],
        warnings:           rich?.review?.warnings || [],
        // Metadata
        imageUrl,
        storagePath: filePath,
        scannedAt:   admin.firestore.FieldValue.serverTimestamp(),
        status:      'pending_review',
      };

      const docRef = await db.collection('contract_scans').add(docData);
      console.log(`[save-contract-scan] Saved ${docRef.id} for gym ${gymId}, contract ${legacy.contractNumber}, confidence ${rich?.review?.overallConfidence}`);
      return res.json({ ok: true, id: docRef.id, imageUrl, overallConfidence: rich?.review?.overallConfidence });

    } catch (err) {
      console.error('[save-contract-scan] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/contracts ────────────────────────────────────────────────────
  r.get('/api/contracts', verifyAzureToken, requireAdmin, async (req, res) => {
    if (!db) return res.status(500).json({ error: 'Firebase non disponible' });
    try {
      const { gymId, limit: lim = 100, status } = req.query;
      let query = db.collection('contract_scans').orderBy('scannedAt', 'desc').limit(Number(lim));
      if (gymId)  query = query.where('gymId', '==', gymId);
      if (status) query = query.where('status', '==', status);

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

  // ── PATCH /api/contracts/:id ─────────────────────────────────────────────
  r.patch('/api/contracts/:id', verifyAzureToken, requireAdmin, express.json({ limit: '5mb' }), async (req, res) => {
    if (!db) return res.status(500).json({ error: 'Firebase non disponible' });
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: 'ID requis' });

    try {
      const allowed = [
        'contractNumber','nom','prenom','cin','dateNaissance','periodFrom','periodTo',
        'subscriptionAmount','phone','ville','status','notes','richExtraction',
      ];
      const updates = {};
      for (const key of allowed) {
        if (req.body[key] !== undefined) updates[key] = req.body[key];
      }
      if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'Aucun champ à mettre à jour' });

      updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      if (updates.status === 'confirmed' && !updates.confirmedBy) {
        updates.confirmedBy = req.user?.preferred_username || req.user?.name || 'admin';
        updates.confirmedAt = admin.firestore.FieldValue.serverTimestamp();
      }

      await db.collection('contract_scans').doc(id).update(updates);
      console.log(`[PATCH /api/contracts/${id}] Updated: ${Object.keys(updates).join(', ')}`);
      return res.json({ ok: true, id, updated: Object.keys(updates) });
    } catch (err) {
      console.error(`[PATCH /api/contracts/${id}] Error:`, err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  return r;
}

module.exports = router;
