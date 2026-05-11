'use strict';
// Seed script: Casa Lady Anfa (casa2) — Day 8: 08/05/2026
require('dotenv').config();
const admin = require('firebase-admin');

if (!admin.apps.length) {
  const serviceAccount = require('../serviceAccount.json');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const GYM_ID = 'casa2';
const DATE   = '2026-05-08';
const DOC_ID = `${GYM_ID}_${DATE}`;

// Notes:
//  - 13979 / 12076 → complément abonnement existant
//  - N0981-0990    → renouvellement carnet 10 séances coaching (DALAL)
//  - 15139 / 15140 → moukrim (inscrites day 3 avance 500 DH) — complement 2ans : espèces + chèque
//  - 15146         → agass khouloud (inscrite day 2 avance 1000 DH) — complement 2ans : chèque
const entries = [
  { contrat: '13979',      commercial: 'DALAL', nom: 'JABRI RADIA',            cin: 'BE912553', tel: '664709792', tpe: 3900, espece: 0,    virement: 0, cheque: 0,    abonnement: 'CMP 2 ANS',                    note_reste: '' },
  { contrat: 'N0981-0990', commercial: 'DALAL', nom: 'SIHAM HABRI',            cin: 'BK615494', tel: '661924866', tpe: 0,    espece: 2400, virement: 0, cheque: 0,    abonnement: 'RENOUVELLEMENT 10 S COACHING',  note_reste: 'Carnet coaching: N0981-0990' },
  { contrat: '12076',      commercial: 'DALAL', nom: 'KHADIJA EL GHIGHAI',     cin: 'BJ214166', tel: '694361977', tpe: 0,    espece: 2000, virement: 0, cheque: 0,    abonnement: 'CMP 1 AN',                     note_reste: '' },
  { contrat: '15139',      commercial: 'DALAL', nom: 'MOUKRIM FATIMA ZAHRA',   cin: 'BK363539', tel: '679229086', tpe: 0,    espece: 1500, virement: 0, cheque: 3900, abonnement: 'COMP 2 ANS',                   note_reste: '' },
  { contrat: '15140',      commercial: 'DALAL', nom: 'MOUKRIM ASMAA',          cin: 'BK642535', tel: '622628424', tpe: 0,    espece: 1500, virement: 0, cheque: 3900, abonnement: 'COMP 2 ANS',                   note_reste: '' },
  { contrat: '15146',      commercial: 'DALAL', nom: 'AGASS KHOULOUD',         cin: 'M528530',  tel: '640720772', tpe: 0,    espece: 0,    virement: 0, cheque: 4900, abonnement: 'COMP 2 ANS',                   note_reste: '' },
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
      console.log(`  ✅ ${e.contrat.padEnd(12)} | ${e.nom.padEnd(26)} | ${String(prix).padStart(5)} DH | ${e.commercial}`);
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

  console.log('\n' + '─'.repeat(54));
  console.log(`  Résultat : ${ok} OK  |  ${fail} erreurs`);
  console.log(`  CA 08/05/2026 — Casa Lady Anfa`);
  console.log(`    TPE      : ${totalTPE.toLocaleString('fr-MA')} DH`);
  console.log(`    Espèces  : ${totalEspece.toLocaleString('fr-MA')} DH`);
  console.log(`    Chèques  : ${totalCheque.toLocaleString('fr-MA')} DH`);
  console.log(`    Virement : ${totalVirement.toLocaleString('fr-MA')} DH`);
  console.log(`    ────────────────────`);
  console.log(`    TOTAL CA : ${totalCA.toLocaleString('fr-MA')} DH`);
  console.log('─'.repeat(54) + '\n');

  process.exit(fail > 0 ? 1 : 0);
}

seed().catch(err => { console.error('Fatal:', err); process.exit(1); });
