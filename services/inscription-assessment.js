'use strict';
// services/inscription-assessment.js
// Smarter inscription quality assessment for MegaFit.
//
// The old assessment asked an LLM to do EVERYTHING (phone/CIN format, price
// matching) against a catalog that had been filtered down to `price > 0` — but
// most real formulas store the price INSIDE the name ("12 MOIS LOCAL - 4000",
// "24 MOIS - BLACK FRIDAY LOCAL", price:0), so the model never saw them and
// hard-failed valid inscriptions as "Abonnement inconnu / Prix incompatible".
//
// This engine is DETERMINISTIC (rules for facts) and TOLERANT:
//   • prices are read from the `price` field OR parsed from the name;
//   • subscriptions are fuzzy-matched (duration + access) — no exact-string need;
//   • unknown formulas & promos become amber "à vérifier", never red errors;
//   • phone/CIN/fields are checked with regex (reliable), not the LLM;
//   • red = genuinely blocking; amber = verify; green = clean.
// The LLM (if a key exists) is used ONLY to refine the human message — it can
// never override a hard rule. Works fully even with no LLM key.

const stripAccents = (s) => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '');
const norm = (s) => stripAccents(s).toUpperCase().replace(/[^A-Z0-9]+/g, ' ').trim();
const tokens = (s) => norm(s).split(' ').filter(Boolean);

// Price embedded in a formula name, e.g. "12 MOIS LOCAL - 4000" → 4000,
// "12 MOIS - MULTI 5250" → 5250. Ignores small duration numbers (7,15,24…).
function parsePriceFromName(name) {
  const nums = (String(name || '').match(/\d{3,6}/g) || []).map(Number).filter((n) => n >= 300 && n <= 100000);
  return nums.length ? Math.max(...nums) : 0;
}
const effectivePrice = (o) => (Number(o?.price) > 0 ? Number(o.price) : parsePriceFromName(o?.name));

const ACCESS_TOKENS = ['LOCAL', 'MULTI', 'KIDS', 'CASA', 'ANFA', 'LADY', 'FES', 'SAISS', 'MARJANE', 'PILATES'];
const accessOf = (t) => t.filter((x) => ACCESS_TOKENS.includes(x));
// Duration signature: the number(s) + unit words (MOIS/AN/ANS/JOURS/ENTREES/TICKETS…)
const durationOf = (t) => t.filter((x) => /^\d{1,2}$/.test(x) || ['MOIS', 'AN', 'ANS', 'JOUR', 'JOURS', 'ENTREE', 'ENTREES', 'TICKET', 'TICKETS', 'SEMAINE', 'JOURNALIER'].includes(x));

function scoreMatch(target, cand) {
  const setC = new Set(cand);
  const common = target.filter((x) => setC.has(x)).length;
  let s = common / Math.max(target.length, cand.length);
  // Reward duration + access agreement so "12 MOIS LOCAL" prefers the LOCAL entry.
  const dT = durationOf(target).join(''), dC = durationOf(cand).join('');
  if (dT && dT === dC) s += 0.25;
  const aT = accessOf(target).join(''), aC = accessOf(cand).join('');
  if (aT && aT === aC) s += 0.2;
  return s;
}

// Best catalog match for a submitted subscription name. Returns { name, note,
// effectivePrice, score, weak } or null when nothing plausibly matches.
function matchSubscription(subName, groups) {
  const target = tokens(subName);
  if (!target.length) return null;
  let best = null, bestScore = 0;
  for (const g of (groups || [])) {
    for (const o of (g.options || [])) {
      if (!o?.name) continue;
      const s = scoreMatch(target, tokens(o.name));
      if (s > bestScore) { bestScore = s; best = { name: o.name, note: o.note || '', effectivePrice: effectivePrice(o), score: s }; }
    }
  }
  if (!best) return null;
  if (bestScore >= 0.6) return best;
  if (bestScore >= 0.4) return { ...best, weak: true };
  return null;
}

const isEntryBased = (subName) => /ENTREE|TICKET|CARNET|JOURNALIER|SEANCE/i.test(stripAccents(subName));

const validPhone = (p) => /^0[5-7]\d{8}$/.test(String(p || '').replace(/[^\d]/g, ''));
const validCIN = (c) => /^[A-Za-z]{1,2}\d{5,7}$/.test(String(c || '').trim());
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || '').trim());

/**
 * Deterministic assessment.
 * @param d { subscriptionName, subPrice, totalDue, totalPaid, balance, phone, email, cin, nom, prenom, dateNaissance, periodFrom, periodTo }
 * @param groups subscriptionGroups from the gym config
 * @returns { status:'ok'|'warning'|'error', message, issues[], matched, expectedPrice }
 */
function assessInscription(d = {}, groups = []) {
  const issues = [];
  let worst = 'ok';
  const bump = (level) => { const rank = { ok: 0, warning: 1, error: 2 }; if (rank[level] > rank[worst]) worst = level; };
  const add = (level, text) => { issues.push(text); bump(level); };

  const subName = d.subscriptionName || '';
  const subPrice = Number(d.subPrice || 0);
  const totalDue = Number(d.totalDue || 0);
  const totalPaid = Number(d.totalPaid || 0);
  const balance = Number(d.balance || 0);

  // ── Identity / format (rules — reliable) ────────────────────────────────────
  if (!String(d.nom || '').trim() || !String(d.prenom || '').trim()) add('error', 'Nom ou prénom manquant');
  if (d.phone && !validPhone(d.phone)) add('error', 'Téléphone invalide (format marocain attendu)');
  else if (!d.phone) add('warning', 'Téléphone manquant');
  if (d.cin && !validCIN(d.cin)) add('warning', 'CIN à vérifier (format inhabituel)');
  if (d.email && !validEmail(d.email)) add('warning', 'Email invalide');
  if (!String(d.dateNaissance || '').trim()) add('warning', 'Date de naissance manquante');
  if (!isEntryBased(subName) && !(d.periodFrom && d.periodTo)) add('warning', 'Période (du/au) manquante');

  // ── Subscription + price coherence (fuzzy + tolerant) ───────────────────────
  const matched = matchSubscription(subName, groups);
  const expectedPrice = matched ? matched.effectivePrice : 0;

  // All catalog prices for the SAME duration (so "1 MOIS MULTI" at 1200 still
  // matches the real "1 MOIS MULTI CASA" 1200 variant instead of being flagged).
  const durSig = durationOf(tokens(subName)).join('');
  const sameDurPrices = [];
  for (const g of (groups || [])) {
    for (const o of (g.options || [])) {
      if (o?.name && durSig && durationOf(tokens(o.name)).join('') === durSig) {
        const p = effectivePrice(o); if (p > 0) sameDurPrices.push(p);
      }
    }
  }
  const within = (a, b) => b > 0 && Math.abs(a - b) / b <= 0.10;

  if (!subName) {
    add('error', 'Abonnement manquant');
  } else if (!matched) {
    add('warning', `Abonnement "${subName}" non reconnu — à vérifier`);
  } else if (subPrice > 0) {
    const priceOk = within(subPrice, expectedPrice) || sameDurPrices.some((p) => within(subPrice, p));
    // Only flag when the amount matches NO real catalog price for this duration,
    // and we actually have an official tariff to compare against. Promos / free-
    // price formulas (expectedPrice 0, no numeric tariff) are trusted.
    if (!priceOk && expectedPrice > 0) add('warning', `Prix ${subPrice} DH hors tarif (~${expectedPrice} DH) — à vérifier`);
  }

  // ── Payment coverage (partial payment is fine when a reste is recorded) ──────
  if (totalDue > 0) {
    const covered = totalPaid + balance; // what the contract accounts for
    if (covered < totalDue * 0.9) add('warning', 'Total (payé + reste) inférieur au montant dû');
    if (totalPaid > 0 && totalPaid < totalDue * 0.4 && balance <= 0) add('error', 'Paiement trop faible sans reste enregistré');
  }

  // ── Human message ───────────────────────────────────────────────────────────
  let message;
  if (worst === 'ok') message = 'Inscription valide';
  else if (worst === 'warning') message = issues[0] || 'À vérifier';
  else message = issues.find((i) => /manquant|invalide|trop faible/i.test(i)) || 'Problème critique détecté';

  return { status: worst, message, issues, matched: matched ? matched.name : null, expectedPrice };
}

module.exports = { assessInscription, parsePriceFromName, matchSubscription, validPhone, validCIN, effectivePrice, norm };
