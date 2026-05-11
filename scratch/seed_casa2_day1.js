'use strict';
// Seed script: Casa Lady Anfa (casa2) — Day 1: 01/05/2026
// Usage: node scratch/seed_casa2_day1.js

require('dotenv').config();
const admin = require('firebase-admin');

// ── Firebase init ────────────────────────────────────────────────────────────
if (!admin.apps.length) {
  const serviceAccount = require('../serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const GYM_ID = 'casa2';
const DATE   = '2026-05-01';
const DOC_ID = `${GYM_ID}_${DATE}`;

// ── Day 1 entries (01/05/2026) ───────────────────────────────────────────────
// AV/COMP column legend:
//   2ans / av 2ans  → Abonnement 2 ANS (avance / nouvelle inscription)
//   comp 2ans       → Complément 2 ANS (payer reste)
//   cmp 3mois       → Complément 3 MOIS (payer reste)
//   cmp 2ans        → Complément 2 ANS (payer reste)

const entries = [
  // N°     | COMMERCIAL | NOM & PRENOM         | CIN       | TEL         | TPE  | ESPECE | VIREMENT | CHEQUE | AV/COMP
  { contrat: '15132', commercial: 'HIBA', nom: 'ZAHIR JAMILA',         cin: 'BE503313', tel: '668191412', tpe: 5900, espece: 0,    virement: 0, cheque: 0,    abonnement: '2 ANS' },
  { contrat: '15133', commercial: 'HIBA', nom: 'EL MAZHARI AYA',       cin: 'BK648711', tel: '656926110', tpe: 5900, espece: 0,    virement: 0, cheque: 0,    abonnement: '2 ANS' },
  { contrat: '15134', commercial: 'DALAL',nom: 'FARHI OUAFAE',         cin: 'MC259452', tel: '641957188', tpe: 2000, espece: 0,    virement: 0, cheque: 0,    abonnement: '2 ANS' },
  { contrat: '15129', commercial: 'HIBA', nom: 'BOULYOUCH MALIKA',     cin: 'JE152812', tel: '697306274', tpe: 0,    espece: 2750, virement: 0, cheque: 2950, abonnement: 'COMP 2 ANS' },
  { contrat: '15130', commercial: 'HIBA', nom: 'IJMOUAANE MALAK',      cin: '15ANS',    tel: '697306274', tpe: 0,    espece: 2750, virement: 0, cheque: 2950, abonnement: 'COMP 2 ANS' },
  { contrat: '15131', commercial: 'HIBA', nom: 'IJMOUAANE HOUDA',      cin: 'BK754209', tel: '694168191', tpe: 0,    espece: 2750, virement: 0, cheque: 2950, abonnement: 'COMP 2 ANS' },
  { contrat: '15114', commercial: 'DALAL',nom: 'RAJI NOURA',           cin: '',         tel: '660907497', tpe: 0,    espece: 5000, virement: 0, cheque: 0,    abonnement: '2 ANS' },
  { contrat: '15104', commercial: 'HIBA', nom: 'LAGHLALI DOUAA',       cin: 'WA354377', tel: '655550457', tpe: 0,    espece: 1700, virement: 0, cheque: 0,    abonnement: 'CMP 3 MOIS' },
  { contrat: '15105', commercial: 'HIBA', nom: 'LAGHLALI IMANE',       cin: 'WA304263', tel: '658861776', tpe: 0,    espece: 1700, virement: 0, cheque: 0,    abonnement: 'CMP 3 MOIS' },
  { contrat: '15128', commercial: 'HIBA', nom: 'AIT MESSAOUD FATIMA',  cin: 'BH502506', tel: '655482813', tpe: 4900, espece: 0,    virement: 0, cheque: 0,    abonnement: 'CMP 2 ANS' },
];

async function seed() {
  console.log(`\n📋 Seeding ${entries.length} entries for ${GYM_ID} on ${DATE}...\n`);

  // Ensure parent doc exists
  await db.collection('megafit_daily_register').doc(DOC_ID).set(
    { gymId: GYM_ID, date: DATE, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
    { merge: true }
  );

  let ok = 0, fail = 0;

  for (const e of entries) {
    const prix = e.tpe + e.espece + e.virement + e.cheque;
    try {
      await db.collection('megafit_daily_register')
        .doc(DOC_ID)
        .collection('entries')
        .add({
          nom:        e.nom,
          cin:        e.cin,
          tel:        e.tel,
          contrat:    e.contrat,
          commercial: e.commercial,
          prix,
          tpe:        e.tpe,
          espece:     e.espece,
          virement:   e.virement,
          cheque:     e.cheque,
          abonnement: e.abonnement,
          reste:      0,
          note_reste: '',
          location:   GYM_ID,
          source:     'manual_seed',
          createdAt:  admin.firestore.FieldValue.serverTimestamp(),
          createdBy:  'admin_seed',
        });

      console.log(`  ✅ ${e.contrat} | ${e.nom.padEnd(25)} | ${String(prix).padStart(5)} DH | ${e.commercial}`);
      ok++;
    } catch (err) {
      console.error(`  ❌ ${e.contrat} | ${e.nom} → ${err.message}`);
      fail++;
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  const totalTPE      = entries.reduce((s, e) => s + e.tpe, 0);
  const totalEspece   = entries.reduce((s, e) => s + e.espece, 0);
  const totalCheque   = entries.reduce((s, e) => s + e.cheque, 0);
  const totalVirement = entries.reduce((s, e) => s + e.virement, 0);
  const totalCA       = totalTPE + totalEspece + totalCheque + totalVirement;

  console.log('\n' + '─'.repeat(50));
  console.log(`  Résultat : ${ok} OK  |  ${fail} erreurs`);
  console.log(`  CA 01/05/2026 — Casa Lady Anfa`);
  console.log(`    TPE      : ${totalTPE.toLocaleString('fr-MA')} DH`);
  console.log(`    Espèces  : ${totalEspece.toLocaleString('fr-MA')} DH`);
  console.log(`    Chèques  : ${totalCheque.toLocaleString('fr-MA')} DH`);
  console.log(`    Virement : ${totalVirement.toLocaleString('fr-MA')} DH`);
  console.log(`    ────────────────────`);
  console.log(`    TOTAL CA : ${totalCA.toLocaleString('fr-MA')} DH`);
  console.log('─'.repeat(50) + '\n');

  process.exit(fail > 0 ? 1 : 0);
}

seed().catch(err => { console.error('Fatal:', err); process.exit(1); });
