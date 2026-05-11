'use strict';
// Seed script: Casa Lady Anfa (casa2) — Day 9: 09/05/2026
require('dotenv').config();
const admin = require('firebase-admin');

if (!admin.apps.length) {
  const serviceAccount = require('../serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const GYM_ID = 'casa2';
const DATE   = '2026-05-09';
const DOC_ID = `${GYM_ID}_${DATE}`;

const entries = [
  { contrat: '15051', commercial: 'DALAL', nom: 'HAJAOUI ISRAE',  cin: 'GD0685099', tel: '660505293', tpe: 1000, espece: 0,    virement: 0, cheque: 0, abonnement: '1 MOIS',      note_reste: '' },
  { contrat: '13888', commercial: 'HIBA',  nom: 'HAJAR JAGHAR',   cin: 'BK663229',  tel: '639678501', tpe: 3000, espece: 0,    virement: 0, cheque: 0, abonnement: 'CMP 2 ANS',   note_reste: '' },
  { contrat: '15119', commercial: 'HIBA',  nom: 'WAFK KAOUTAR',   cin: 'BK387565',  tel: '603451845', tpe: 0,    espece: 1700, virement: 0, cheque: 0, abonnement: 'CMP 3 MOIS',  note_reste: '' },
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
        abonnement: e.abonnement, reste: 0, note_reste: e.note_reste,
        location: GYM_ID, source: 'manual_seed',
        createdAt: admin.firestore.FieldValue.serverTimestamp(), createdBy: 'admin_seed',
      });
      console.log(`  ✅ ${e.contrat} | ${e.nom.padEnd(25)} | ${String(prix).padStart(5)} DH | ${e.commercial}`);
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
  console.log(`  CA 09/05/2026 — Casa Lady Anfa`);
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
