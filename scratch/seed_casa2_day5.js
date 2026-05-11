'use strict';
// Seed script: Casa Lady Anfa (casa2) — Day 5: 05/05/2026
require('dotenv').config();
const admin = require('firebase-admin');

if (!admin.apps.length) {
  const serviceAccount = require('../serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const GYM_ID = 'casa2';
const DATE   = '2026-05-05';
const DOC_ID = `${GYM_ID}_${DATE}`;

const entries = [
  { contrat: '15145', commercial: 'HIBA',  nom: 'FALI CHIRINE',      cin: 'BK709813', tel: '603393445', tpe: 2200, espece: 0,    virement: 0, cheque: 0,    abonnement: '3 MOIS' },
  { contrat: '15146', commercial: 'DALAL', nom: 'AGASS KHOULOUD',    cin: 'M528530',  tel: '640720772', tpe: 0,    espece: 1000, virement: 0, cheque: 0,    abonnement: '2 ANS' },
  { contrat: '14029', commercial: 'HIBA',  nom: 'MIMOUN SAMAH',      cin: 'BK706813', tel: '694385679', tpe: 0,    espece: 1700, virement: 0, cheque: 0,    abonnement: 'COMP 3 MOIS' },
  { contrat: '15147', commercial: 'HIBA',  nom: 'BANNANI SOUAD',     cin: 'B409973',  tel: '661163771', tpe: 0,    espece: 0,    virement: 0, cheque: 5900, abonnement: '2 ANS' },
];

async function seed() {
  console.log(`\n📋 Seeding ${entries.length} entries for ${GYM_ID} on ${DATE}...\n`);

  await db.collection('megafit_daily_register').doc(DOC_ID).set(
    { gymId: GYM_ID, date: DATE, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
    { merge: true }
  );

  let ok = 0, fail = 0;

  for (const e of entries) {
    const prix = e.tpe + e.espece + e.virement + e.cheque;
    try {
      await db.collection('megafit_daily_register').doc(DOC_ID).collection('entries').add({
        nom: e.nom, cin: e.cin, tel: e.tel, contrat: e.contrat, commercial: e.commercial,
        prix, tpe: e.tpe, espece: e.espece, virement: e.virement, cheque: e.cheque,
        abonnement: e.abonnement, reste: 0, note_reste: '',
        location: GYM_ID, source: 'manual_seed',
        createdAt: admin.firestore.FieldValue.serverTimestamp(), createdBy: 'admin_seed',
      });
      console.log(`  ✅ ${e.contrat} | ${e.nom.padEnd(28)} | ${String(prix).padStart(5)} DH | ${e.commercial}`);
      ok++;
    } catch (err) {
      console.error(`  ❌ ${e.contrat} | ${e.nom} → ${err.message}`);
      fail++;
    }
  }

  const totalTPE      = entries.reduce((s, e) => s + e.tpe, 0);
  const totalEspece   = entries.reduce((s, e) => s + e.espece, 0);
  const totalCheque   = entries.reduce((s, e) => s + e.cheque, 0);
  const totalVirement = entries.reduce((s, e) => s + e.virement, 0);
  const totalCA       = totalTPE + totalEspece + totalCheque + totalVirement;

  console.log('\n' + '─'.repeat(52));
  console.log(`  Résultat : ${ok} OK  |  ${fail} erreurs`);
  console.log(`  CA 05/05/2026 — Casa Lady Anfa`);
  console.log(`    TPE      : ${totalTPE.toLocaleString('fr-MA')} DH`);
  console.log(`    Espèces  : ${totalEspece.toLocaleString('fr-MA')} DH`);
  console.log(`    Chèques  : ${totalCheque.toLocaleString('fr-MA')} DH`);
  console.log(`    Virement : ${totalVirement.toLocaleString('fr-MA')} DH`);
  console.log(`    ────────────────────`);
  console.log(`    TOTAL CA : ${totalCA.toLocaleString('fr-MA')} DH`);
  console.log('─'.repeat(52) + '\n');

  process.exit(fail > 0 ? 1 : 0);
}

seed().catch(err => { console.error('Fatal:', err); process.exit(1); });
