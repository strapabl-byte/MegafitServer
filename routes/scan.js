// routes/scan.js
// 📷 CIN + Contract Scanner — Smart Multi-Crop GPT-5.5 Vision
//
// POST /public/scan-cin            { image, side }          → Groq Llama 4 Scout (fast ID OCR)
// POST /public/scan-contract       { image, mode? }         → OpenAI Responses API, 6 crops, Structured Outputs
// POST /public/save-contract-scan  { image, fields, gymId, commercial, corrections }
// GET  /api/contracts              (admin only) — list saved contract scans
// PATCH /api/contracts/:id         (admin only) — update fields / status

'use strict';
const express = require('express');
const sharp   = require('sharp');
const OpenAI  = require('openai');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

// ── Model config ──────────────────────────────────────────────────────────────
const GROQ_VISION_URL  = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_CIN_MODEL   = 'meta-llama/llama-4-scout-17b-16e-instruct';
const OPENAI_URL       = 'https://api.openai.com/v1/chat/completions';
const OPENAI_SMART     = 'gpt-5.5-2026-04-23'; // Smart Scan — confirmed available on this account
const OPENAI_FAST      = 'gpt-4o-mini';         // Quick Scan — fast + cost-effective

// ── Calibrated crop map for MegaFit A4 contract (% of page) ───────────────────
// Skips logo/header at top 18%, maps exactly to content zones
const CROP_MAP = {
  topLeft:  { left: 0.03, top: 0.18, width: 0.48, height: 0.28 }, // identity: nom, prénom, CIN, naissance
  topRight: { left: 0.50, top: 0.18, width: 0.47, height: 0.28 }, // phone, ville, adresse, urgence
  midLeft:  { left: 0.03, top: 0.43, width: 0.48, height: 0.38 }, // dates abonnement, durée, montant
  midRight: { left: 0.50, top: 0.43, width: 0.47, height: 0.38 }, // options, paiement, mode
  bottom:   { left: 0.03, top: 0.78, width: 0.94, height: 0.20 }, // accès, signature, date
};

// ── Image preprocessing with sharp ───────────────────────────────────────────
async function preprocessAndCrop(base64DataUri) {
  const match = base64DataUri.match(/^data:(image\/\w+);base64,(.+)$/);
  if (!match) throw new Error('Format image invalide (attendu: data:image/...;base64,...)');
  const inputBuffer = Buffer.from(match[2], 'base64');

  const raw = sharp(inputBuffer).rotate();
  const meta = await raw.clone().metadata();
  const origW = meta.width  || 1200;
  const origH = meta.height || 1700;

  const targetW = Math.min(Math.max(origW, 1000), 2000);
  const targetH = Math.round((targetW / origW) * origH);

  const enhanced = raw.clone()
    .resize(targetW, targetH, { fit: 'fill' })
    .normalise()
    .sharpen({ sigma: 1.0, m1: 0.5, m2: 2.0 })
    .jpeg({ quality: 85 });

  const fullBuf = await enhanced.toBuffer();
  const fullB64 = `data:image/jpeg;base64,${fullBuf.toString('base64')}`;

  const base = sharp(fullBuf);
  const cropToB64 = async (left, top, width, height) => {
    const w = Math.min(width,  targetW - left);
    const h = Math.min(height, targetH - top);
    if (w <= 0 || h <= 0) return fullB64;
    const buf = await base.clone()
      .extract({ left, top, width: w, height: h })
      .normalise()
      .sharpen({ sigma: 1.2, m1: 0.6, m2: 2.5 })
      .jpeg({ quality: 90 })
      .toBuffer();
    return `data:image/jpeg;base64,${buf.toString('base64')}`;
  };

  const px = (box) => ({
    left:   Math.round(targetW * box.left),
    top:    Math.round(targetH * box.top),
    width:  Math.round(targetW * box.width),
    height: Math.round(targetH * box.height),
  });

  const [topLeft, topRight, midLeft, midRight, bottom] = await Promise.all(
    ['topLeft','topRight','midLeft','midRight','bottom'].map(k => {
      const p = px(CROP_MAP[k]);
      return cropToB64(p.left, p.top, p.width, p.height);
    })
  );

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

// ── OpenAI Responses API — Structured Outputs (guaranteed valid JSON schema) ────
const GYM_CONTRACT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['documentType','contract','member','subscription','options','payment','access','signature','review'],
  properties: {
    documentType: { type: 'string', enum: ['gym_membership_contract'] },
    contract: {
      type: 'object', additionalProperties: false,
      required: ['club','commercial','contractNumber','isRenewal'],
      properties: {
        club:           { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        commercial:     { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        contractNumber: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        isRenewal:      { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    member: {
      type: 'object', additionalProperties: false,
      required: ['civility','lastName','firstName','cin','birthDate','address','postalCode','city','phone','email','emergencyContactName','emergencyPhone'],
      properties: {
        civility:             { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        lastName:             { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        firstName:            { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        cin:                  { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        birthDate:            { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        address:              { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        postalCode:           { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        city:                 { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        phone:                { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        email:                { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        emergencyContactName: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        emergencyPhone:       { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    subscription: {
      type: 'object', additionalProperties: false,
      required: ['durationDays','durationWeeks','durationMonths','durationYears','startDate','endDate','totalAmountDhs'],
      properties: {
        durationDays:    { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        durationWeeks:   { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        durationMonths:  { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        durationYears:   { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        startDate:       { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        endDate:         { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        totalAmountDhs:  { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    options: {
      type: 'object', additionalProperties: false,
      required: ['withTransfer','withoutTransfer','privateCoaching','insurance','covidInsurance'],
      properties: {
        withTransfer:    { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        withoutTransfer: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        privateCoaching: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        insurance:       { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        covidInsurance:  { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    payment: {
      type: 'object', additionalProperties: false,
      required: ['paymentMethod','cashAmountDhs','cardAmountDhs','chequeAmountDhs','transferAmountDhs','remainingAmountDhs'],
      properties: {
        paymentMethod:      { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        cashAmountDhs:      { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        cardAmountDhs:      { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        chequeAmountDhs:    { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        transferAmountDhs:  { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        remainingAmountDhs: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'number' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    access: {
      type: 'object', additionalProperties: false,
      required: ['local','multiclub'],
      properties: {
        local:     { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        multiclub: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    signature: {
      type: 'object', additionalProperties: false,
      required: ['city','date','memberSigned','staffSigned'],
      properties: {
        city:         { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        date:         { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'string' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        memberSigned: { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
        staffSigned:  { type: 'object', additionalProperties: false, required: ['value','raw','confidence','needsReview'], properties: { value: { anyOf: [{ type: 'boolean' }, { type: 'null' }] }, raw: { anyOf: [{ type: 'string' }, { type: 'null' }] }, confidence: { type: 'number' }, needsReview: { type: 'boolean' } } },
      },
    },
    review: {
      type: 'object', additionalProperties: false,
      required: ['overallConfidence','fieldsNeedingReview','warnings'],
      properties: {
        overallConfidence:   { type: 'number', minimum: 0, maximum: 1 },
        fieldsNeedingReview: { type: 'array', items: { type: 'string' } },
        warnings:            { type: 'array', items: { type: 'string' } },
      },
    },
  },
};

// ── OpenAI Responses API — Structured Outputs (guaranteed valid JSON schema) ────
async function callOpenAIResponses(crops, systemPrompt, model) {
  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  const imageInputs = [
    { type: 'input_image', image_url: crops.full,     detail: 'low'  },
    { type: 'input_image', image_url: crops.topLeft,  detail: 'high' },
    { type: 'input_image', image_url: crops.topRight, detail: 'high' },
    { type: 'input_image', image_url: crops.midLeft,  detail: 'high' },
    { type: 'input_image', image_url: crops.midRight, detail: 'high' },
    { type: 'input_image', image_url: crops.bottom,   detail: 'high' },
  ];

  const response = await openai.responses.create({
    model,
    reasoning: { effort: 'high' },
    input: [
      { role: 'system', content: [{ type: 'input_text', text: systemPrompt }] },
      { role: 'user',   content: [
        { type: 'input_text', text: 'Extract this gym membership contract into structured JSON.' },
        ...imageInputs,
      ]},
    ],
    text: {
      format: {
        type:   'json_schema',
        name:   'gym_contract_extraction',
        strict: true,
        schema: GYM_CONTRACT_SCHEMA,
      },
    },
    max_output_tokens: 10000,
  });

  return response.output_parsed || (response.output_text ? JSON.parse(response.output_text) : null);
}

// ── OpenAI Vision call — multi-image (chat/completions fallback) ───────────
async function callOpenAIMultiImage(crops, systemPrompt, model = OPENAI_SMART) {
  const OPENAI_KEY = process.env.OPENAI_API_KEY;
  if (!OPENAI_KEY) throw new Error('OPENAI_API_KEY non configurée.');

  const imageBlocks = [
    toImageBlock(crops.full,     'low'),
    toImageBlock(crops.topLeft,  'high'),
    toImageBlock(crops.topRight, 'high'),
    toImageBlock(crops.midLeft,  'high'),
    toImageBlock(crops.midRight, 'high'),
    toImageBlock(crops.bottom,   'high'),
  ];

  const res = await fetch(OPENAI_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${OPENAI_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
              type: 'text',
              text: 'Voici le contrat complet (image 1) suivi de 5 sections recadrées (images 2–6). Extrais toutes les données visibles dans le JSON demandé.',
            },
            ...imageBlocks,
          ],
        },
      ],
      max_completion_tokens: 8000,
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

// ── Build system prompt — optionally enhanced with human corrections ──────────
function buildSystemPrompt(corrections = []) {
  const base = `
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

  if (!corrections || corrections.length === 0) return base;

  // Deduplicate by field+aiValue to avoid noise
  const seen = new Set();
  const unique = corrections.filter(c => {
    const key = `${c.field}|${c.aiValue}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });

  const examples = unique.map(c =>
    `  - field "${c.field}": AI read "${c.aiValue}" → human corrected to "${c.humanValue}"`
  ).join('\n');

  return base + `\n\nHUMAN CORRECTION HISTORY (${unique.length} past corrections — learn from these patterns to improve accuracy):\n${examples}\n\nApply these learned patterns: pay extra attention to similar handwriting, digit/letter confusion (0/O, 1/l/I, 5/S, 8/B), and spacing in the corrected fields above.`;
}

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

      // ── Step 2: Fetch recent human corrections from Firestore (few-shot learning) ──
      let pastCorrections = [];
      if (db) {
        try {
          const corrSnap = await db.collection('scan_corrections')
            .orderBy('correctedAt', 'desc')
            .limit(40)
            .get();
          pastCorrections = corrSnap.docs.map(d => d.data());
          if (pastCorrections.length > 0)
            console.log(`[scan-contract] Injecting ${pastCorrections.length} past corrections into prompt`);
        } catch (e) {
          console.warn('[scan-contract] Could not fetch corrections:', e.message);
        }
      }
      const systemPrompt = buildSystemPrompt(pastCorrections);

      // ── Step 3: Call vision model (Responses API → fallback to chat/completions) ──
      let parsed = null;
      let usedResponsesAPI = false;
      if (useOpenAI) {
        // Try Responses API first (Structured Outputs — guaranteed valid JSON)
        try {
          console.log('[scan-contract] Trying Responses API with Structured Outputs...');
          parsed = await callOpenAIResponses(crops, systemPrompt, model);
          usedResponsesAPI = true;
          console.log('[scan-contract] Responses API success');
        } catch (respErr) {
          console.warn('[scan-contract] Responses API failed, falling back to chat/completions:', respErr.message);
        }
      }
      // Fallback: chat/completions (raw fetch)
      if (!parsed) {
        let scanRes;
        if (useOpenAI) {
          scanRes = await callOpenAIMultiImage(crops, systemPrompt, model);
        } else {
          console.warn('[scan-contract] No OPENAI_API_KEY — using Groq fallback');
          scanRes = await callGroqContractFallback(crops, systemPrompt);
        }
        if (!scanRes.ok) {
          const errText = await scanRes.text();
          console.error('[scan-contract] Vision error:', errText);
          return res.status(502).json({ error: 'Erreur Vision API', detail: errText });
        }
        const data = await scanRes.json();
        const rawText = data.choices?.[0]?.message?.content || '{}';
        console.log('[scan-contract] chat/completions response length:', rawText.length);
        try {
          const jsonMatch = rawText.match(/\{[\s\S]*\}/);
          if (!jsonMatch) throw new Error('No JSON in response');
          parsed = JSON.parse(jsonMatch[0]);
        } catch (parseErr) {
          console.error('[scan-contract] JSON parse error:', parseErr.message);
          parsed = {};
        }
      }

      // ── Step 4: Normalise into schema ──────────────────────────────────────
      let rich = normaliseExtracted(parsed || {});

      // ── Step 5: Business validation pass ───────────────────────────────────
      const warnings = validateContract(rich);
      if (warnings.length) console.log('[scan-contract] Validation warnings:', warnings);

      // ── Step 6: Deep Scan fallback — rescan only uncertain fields ───────────
      let deepScanRun = false;
      if (useOpenAI && rich.review.overallConfidence < 0.85 && rich.review.fieldsNeedingReview.length > 0) {
        console.log(`[scan-contract] Confidence ${rich.review.overallConfidence} < 0.85, running Deep Scan on ${rich.review.fieldsNeedingReview.length} uncertain fields...`);
        try {
          const uncertainFields = rich.review.fieldsNeedingReview.join(', ');
          const deepPrompt = `${systemPrompt}\n\nDEEP SCAN — SECOND PASS:\nThe first extraction had uncertain fields: ${uncertainFields}\nFocus exclusively on re-reading these fields from the crops. Return only corrected values for uncertain fields; keep all other fields exactly as they are. Apply maximum attention to these zones.`;

          // Identify which crops are relevant based on uncertain field paths
          const needsTop  = uncertainFields.match(/civility|lastName|firstName|cin|birthDate|address|postalCode|city|phone|email|emergency|commercial|contractNumber/i);
          const needsMid  = uncertainFields.match(/subscription|startDate|endDate|duration|total|payment|cash|card|cheque|transfer|remaining|options|coaching|insurance/i);
          const needsBot  = uncertainFields.match(/access|signature|memberSigned|staffSigned|date|local|multiclub/i);

          const deepCrops = {
            full:     crops.full,
            topLeft:  needsTop ? crops.topLeft  : crops.full,
            topRight: needsTop ? crops.topRight : crops.full,
            midLeft:  needsMid ? crops.midLeft  : crops.full,
            midRight: needsMid ? crops.midRight : crops.full,
            bottom:   needsBot ? crops.bottom   : crops.full,
          };

          let deepParsed = null;
          try {
            deepParsed = await callOpenAIResponses(deepCrops, deepPrompt, model);
          } catch {
            const deepRes = await callOpenAIMultiImage(deepCrops, deepPrompt, model);
            if (deepRes.ok) {
              const deepData = await deepRes.json();
              const deepText = deepData.choices?.[0]?.message?.content || '{}';
              const m = deepText.match(/\{[\s\S]*\}/);
              if (m) deepParsed = JSON.parse(m[0]);
            }
          }

          if (deepParsed) {
            // Merge: only overwrite fields that were uncertain
            const deepRich = normaliseExtracted(deepParsed);
            rich.review.fieldsNeedingReview.forEach(path => {
              const parts = path.split('.');
              if (parts.length === 2) {
                const [section, key] = parts;
                if (deepRich[section]?.[key]?.value !== null && deepRich[section]?.[key]?.confidence > (rich[section]?.[key]?.confidence || 0)) {
                  rich[section][key] = deepRich[section][key];
                }
              }
            });
            validateContract(rich); // revalidate after merge
            deepScanRun = true;
            console.log(`[scan-contract] Deep Scan complete. New confidence: ${rich.review.overallConfidence}`);
          }
        } catch (deepErr) {
          console.warn('[scan-contract] Deep Scan failed (non-critical):', deepErr.message);
        }
      }

      // ── Step 7: Return both rich + legacy flat ──────────────────────────────
      const legacy = flattenToLegacy(rich);
      console.log(`[scan-contract] Done. Confidence: ${rich.review.overallConfidence}, uncertain: ${rich.review.fieldsNeedingReview.length}, API: ${usedResponsesAPI ? 'Responses' : 'chat/completions'}, deepScan: ${deepScanRun}`);

      return res.json({
        rich,
        legacy,
        model: model || 'groq-fallback',
        useOpenAI,
        usedResponsesAPI,
        deepScanRun,
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
    const { image, rich, fields = {}, gymId, commercial, corrections = [] } = req.body;
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

      // ── Save field corrections for future few-shot learning ─────────────────
      const validCorrections = (corrections || []).filter(
        c => c.field && c.aiValue !== undefined && c.humanValue !== undefined
           && String(c.aiValue).trim() !== String(c.humanValue).trim()
      );
      if (validCorrections.length > 0) {
        const batch = db.batch();
        validCorrections.forEach(c => {
          const ref = db.collection('scan_corrections').doc();
          batch.set(ref, {
            field:       c.field,
            aiValue:     String(c.aiValue),
            humanValue:  String(c.humanValue),
            gymId:       gymId || 'unknown',
            contractId:  docRef.id,
            correctedAt: admin.firestore.FieldValue.serverTimestamp(),
          });
        });
        await batch.commit();
        console.log(`[save-contract-scan] Stored ${validCorrections.length} corrections for future learning`);
      }

      return res.json({ ok: true, id: docRef.id, imageUrl, overallConfidence: rich?.review?.overallConfidence, correctionsSaved: validCorrections.length });

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
