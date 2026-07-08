'use strict';
// Proves the smarter inscription assessment no longer red-flags valid inscriptions.
// Uses the REAL default catalog from routes/config.js. Pure function — no creds.
// Run: node test/assessment.selftest.js

const { assessInscription } = require('../services/inscription-assessment');
const { DEFAULT_SUBSCRIPTION_GROUPS: CAT } = require('../routes/config');

let pass = 0, fail = 0;
const check = (name, cond, extra = '') => { if (cond) { pass++; console.log('  ✓', name); } else { fail++; console.error('  ✗', name, extra); } };

// A clean identity so only the subscription/price dimension is exercised.
const ID = { phone: '0690898197', nom: 'TEST', prenom: 'MEMBRE', cin: 'AB123456', dateNaissance: '1990-01-01', periodFrom: '2026-07-08', periodTo: '2027-07-08' };
const A = (over) => assessInscription({ ...ID, ...over }, CAT);

// ── The exact cases from the screenshot that were wrongly RED ────────────────
const kl = A({ subscriptionName: '24 MOIS - BLACK FRIDAY LOCAL', subPrice: 6900, totalDue: 6900, totalPaid: 6900, balance: 0 });
check('BLACK FRIDAY promo → not error (was red)', kl.status !== 'error', JSON.stringify(kl));
check('BLACK FRIDAY promo → ok (trusted promo price)', kl.status === 'ok', JSON.stringify(kl));

const em = A({ subscriptionName: '12 MOIS LOCAL', subPrice: 5250, totalDue: 5250, totalPaid: 5250, balance: 0 });
check('12 MOIS LOCAL @5250 (matches a real 12-mois price) → ok (was red)', em.status === 'ok', JSON.stringify(em));

const alami = A({ subscriptionName: '1 MOIS MULTI', subPrice: 1200, totalDue: 1200, totalPaid: 1200, balance: 0 });
check('1 MOIS MULTI @1200 (= MULTI CASA variant) → ok', alami.status === 'ok', JSON.stringify(alami));

const kj = A({ subscriptionName: '10 ENTREES', subPrice: 1000, totalDue: 1000, totalPaid: 1000, balance: 0, periodFrom: '', periodTo: '' });
check('10 ENTREES → not error, période NOT required for carnets', kj.status !== 'error' && !kj.issues.some((i) => /riode/i.test(i)), JSON.stringify(kj));

const hb = A({ subscriptionName: '12 MOIS LOCAL', subPrice: 3500, totalDue: 3500, totalPaid: 3500, balance: 0, cin: 'ZZ' });
check('12 MOIS LOCAL @3500 (below 4000 tariff, bad CIN) → warning, NOT error', hb.status === 'warning', JSON.stringify(hb));

// ── Genuine problems must STILL be caught ────────────────────────────────────
const badPhone = A({ subscriptionName: '1 MOIS LOCAL', subPrice: 1000, totalDue: 1000, totalPaid: 1000, phone: '12345' });
check('invalid phone → error (still caught)', badPhone.status === 'error', JSON.stringify(badPhone));

const noName = A({ subscriptionName: '1 MOIS LOCAL', subPrice: 1000, totalDue: 1000, totalPaid: 1000, prenom: '', nom: '' });
check('missing name → error (still caught)', noName.status === 'error', JSON.stringify(noName));

const tinyPay = A({ subscriptionName: '12 MOIS LOCAL', subPrice: 4000, totalDue: 4000, totalPaid: 200, balance: 0 });
check('paid 200 of 4000 with no reste → error', tinyPay.status === 'error', JSON.stringify(tinyPay));

const partial = A({ subscriptionName: '12 MOIS LOCAL', subPrice: 4000, totalDue: 4000, totalPaid: 2000, balance: 2000 });
check('partial payment with reste recorded → not error', partial.status !== 'error', JSON.stringify(partial));

const unknown = A({ subscriptionName: 'FORMULE INVENTEE XYZ', subPrice: 999, totalDue: 999, totalPaid: 999 });
check('truly unknown formula → warning (not error, not silent)', unknown.status === 'warning', JSON.stringify(unknown));

// ── Summary: none of the valid screenshot cases may be red ───────────────────
const validCases = [kl, em, alami, kj];
check('NONE of the valid screenshot inscriptions are red', validCases.every((c) => c.status !== 'error'));

console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
