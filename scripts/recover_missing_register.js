'use strict';
// recover_missing_register.js
// Run with: node recover_missing_register.js
// Finds all 'awaiting_payment' inscriptions from the last 7 days
// that are missing from the daily register and injects them.
require('dotenv').config();

const admin = require('firebase-admin');
const path  = require('path');
const fs    = require('fs');
const lc    = require('./localCache');

// ── Firebase Init ──────────────────────────────────────────────────────────
let serviceAccount;
const localPath = path.join(__dirname, 'serviceAccount.json');
if (fs.existsSync(localPath)) {
  serviceAccount = require(localPath);
} else {
  console.error('❌ serviceAccount.json not found'); process.exit(1);
}
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

// ── Helpers ────────────────────────────────────────────────────────────────
function planToAbonnement(plan, subscriptionName) {
  if (subscriptionName) return subscriptionName.toUpperCase();
  const map = { Monthly: '1 MOIS', Quarterly: '3 MOIS', 'Semi-Annual': '6 MOIS', Annual: '1 AN' };
  return map[plan] || plan || '1 AN';
}

async function autoRegisterCA({ gymId='dokarat', date, nom, tel, cin, plan, subscriptionName, amount, method, commercial, contrat, payments: split, reste, note }) {
  const today  = date || new Date().toISOString().slice(0, 10);
  const docId  = `${gymId}_${today}`;
  const totalAmt = Number(amount) || 0;
  let tpe=0, espece=0, virement=0, cheque=0;
  if (split && typeof split === 'object') {
    tpe      = Number(split.carte    || split.tpe      || 0);
    espece   = Number(split.espece   || 0);
    virement = Number(split.virement || 0);
    cheque   = Number(split.cheque   || 0);
  } else {
    const m = { 'Espèces':'espece', espece:'espece', TPE:'tpe', 'Carte Bancaire':'tpe', tpe:'tpe', Virement:'virement', 'Chèque':'cheque', Cheque:'cheque', cheque:'cheque' };
    const f = m[method] || 'espece';
    if (f==='tpe') tpe=totalAmt; else if (f==='virement') virement=totalAmt; else if (f==='cheque') cheque=totalAmt; else espece=totalAmt;
  }
  const prix = tpe+espece+virement+cheque || totalAmt;
  const addedDoc = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
    nom:nom||'', tel:tel||'', contrat:contrat||'',
    commercial:(commercial||'FORM').toUpperCase(), cin:cin||'',
    prix, tpe, espece, virement, cheque,
    abonnement: planToAbonnement(plan, subscriptionName),
    reste: Number(reste)||0,
    note_reste: note||(reste>0?`Reste: ${reste} DH`:''),
    source: 'inscription_auto_recovered',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    createdBy: 'recover_script',
  });
  await db.collection('megafit_daily_register').doc(docId).set(
    { gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
    { merge: true }
  );
  const newSnap = await addedDoc.get();
  lc.upsertRegister(gymId, today, [{ id: addedDoc.id, ...newSnap.data() }]);
  console.log(`  ✅ Added: ${nom} | ${prix} DH → ${docId}`);
  return addedDoc.id;
}

// ── Main ───────────────────────────────────────────────────────────────────
async function run() {
  const DAYS_BACK = 7;
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - DAYS_BACK);

  console.log(`\n🔍 Looking for 'awaiting_payment' inscriptions from last ${DAYS_BACK} days...\n`);

  const snap = await db.collection('pending_members')
    .where('status', '==', 'awaiting_payment')
    .get();

  console.log(`Found ${snap.docs.length} total awaiting_payment inscriptions.\n`);

  const recovered = [], skipped = [], errors = [];

  for (const doc of snap.docs) {
    const ins      = doc.data();
    const insGymId  = ins.gymId || 'dokarat';
    const fullName  = `${ins.prenom || ''} ${ins.nom || ''}`.trim();
    const contrat   = ins.contractNumber || '';

    // Determine date
    let dateStr = new Date().toISOString().slice(0, 10);
    if (ins.createdAt?._seconds)       dateStr = new Date(ins.createdAt._seconds * 1000).toISOString().slice(0,10);
    else if (ins.memberCreatedAt?._seconds) dateStr = new Date(ins.memberCreatedAt._seconds * 1000).toISOString().slice(0,10);

    process.stdout.write(`Checking ${fullName || doc.id} (${dateStr}) [${insGymId}]... `);

    // Skip if too old
    if (new Date(dateStr) < cutoff) {
      console.log(`⏭  Skipped (too old)`);
      skipped.push({ id: doc.id, name: fullName, reason: 'Too old (>7 days)' });
      continue;
    }

    // Guard: check Firestore register
    if (contrat) {
      const regDocId  = `${insGymId}_${dateStr}`;
      const existSnap = await db.collection('megafit_daily_register')
        .doc(regDocId).collection('entries')
        .where('contrat', '==', contrat).limit(1).get();
      if (!existSnap.empty) {
        console.log(`⏭  Skipped (already in register)`);
        skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'Already in Firestore register' });
        continue;
      }

      // Guard: check SQLite
      const existInSQLite = lc.db.prepare(
        `SELECT id FROM register_cache WHERE gym_id=? AND contrat=? AND date=? LIMIT 1`
      ).get(insGymId, contrat, dateStr);
      if (existInSQLite) {
        console.log(`⏭  Skipped (already in SQLite)`);
        skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'Already in SQLite register' });
        continue;
      }
    }

    // Payment amounts
    const espece   = Number(ins.payments?.espece   || 0);
    const carte    = Number(ins.payments?.carte    || ins.payments?.tpe || 0);
    const virement = Number(ins.payments?.virement || 0);
    const cheque   = Number(ins.payments?.cheque   || 0);
    const totalPaid = espece + carte + virement + cheque
                   || Number(ins.totals?.paid || ins.totals?.grandTotal || 0);

    if (totalPaid <= 0) {
      console.log(`⏭  Skipped (no payment amount)`);
      skipped.push({ id: doc.id, name: fullName, date: dateStr, reason: 'No payment amount' });
      continue;
    }

    const method = carte>0 ? 'Carte Bancaire' : espece>0 ? 'Espèces' : virement>0 ? 'Virement' : 'Chèque';
    console.log(`\n  → Recovering: ${fullName} | ${totalPaid} DH | ${method}`);

    try {
      await autoRegisterCA({
        gymId: insGymId,
        date: dateStr,
        nom: fullName,
        tel: ins.telephone || '',
        cin: ins.cin || '',
        plan: ins.plan || 'Annual',
        subscriptionName: ins.subscriptionName || '',
        amount: totalPaid,
        method,
        commercial: ins.commercial || 'FORM',
        contrat,
        payments: { espece, carte, virement, cheque },
        reste: Math.max(0, (ins.totals?.grandTotal || 0) - totalPaid),
        note: `[RÉCUPÉRÉ] Inscription N°${contrat}`,
      });
      recovered.push({ id: doc.id, name: fullName, date: dateStr, amount: totalPaid, gymId: insGymId, contrat });
    } catch (e) {
      console.log(`  ❌ Error: ${e.message}`);
      errors.push({ id: doc.id, name: fullName, error: e.message });
    }
  }

  console.log('\n─────────────────────────────────────────────');
  console.log(`✅ RECOVERED (${recovered.length}):`);
  recovered.forEach(r => console.log(`   • ${r.name} | ${r.amount} DH | ${r.date} [${r.gymId}] N°${r.contrat}`));

  console.log(`\n⏭  SKIPPED (${skipped.length}):`);
  skipped.forEach(r => console.log(`   • ${r.name}: ${r.reason}`));

  if (errors.length) {
    console.log(`\n❌ ERRORS (${errors.length}):`);
    errors.forEach(r => console.log(`   • ${r.name}: ${r.error}`));
  }

  console.log('\n─────────────────────────────────────────────');
  console.log(`Done. ${recovered.length} recovered, ${skipped.length} skipped, ${errors.length} errors.`);
  process.exit(0);
}

run().catch(err => { console.error('Fatal:', err); process.exit(1); });
