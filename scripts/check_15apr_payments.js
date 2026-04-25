/**
 * check_15apr_payments.js
 * ────────────────────────
 * Cherche dans TOUTES les collections Firestore liées au 15 avril 2026
 * pour trouver le paiement de 5,900 DH manquant dans le registre.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const db = admin.firestore();

async function main() {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║   RECHERCHE 5,900 DH MANQUANTS – 15 AVRIL 2026 – DOKARAT      ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  // 1. Registre du 15 (déjà vu — rappel)
  console.log('📋 1. Registre Firestore 15 avril (déjà connu) : 11,650 DH (6 membres)\n');

  // 2. Vérifier si le 15 avril a des décaissements qui réduiraient le net
  const decSnap = await db.collection('megafit_daily_register')
    .doc('dokarat_2026-04-15')
    .collection('decaissements')
    .get();
  console.log(`📤 2. Décaissements 15 avril : ${decSnap.size} entrées`);
  if (!decSnap.empty) {
    decSnap.docs.forEach(d => {
      const e = d.data();
      console.log(`     → ${e.label || e.type || 'N/A'}  ${e.montant} DH  status: ${e.status}`);
    });
  }

  // 3. Chercher dans la collection payments pour le 15 avril
  console.log('\n💳 3. Paiements (collection payments) autour du 15 avril...');
  try {
    const paySnap = await db.collection('payments')
      .where('gymId', '==', 'dokarat')
      .where('date', '>=', '2026-04-14')
      .where('date', '<=', '2026-04-16')
      .get();

    if (paySnap.empty) {
      console.log('   Aucun paiement trouvé dans collection "payments"');
    } else {
      paySnap.docs.forEach(d => {
        const e = d.data();
        console.log(`   ${d.id} | ${e.nom || e.memberName} | ${e.montant || e.amount} DH | ${e.date}`);
      });
    }
  } catch(e) { console.log('   Collection "payments" non trouvée ou erreur:', e.message); }

  // 4. Chercher dans inscriptions Firestore pour le 15 avril
  console.log('\n📝 4. Inscriptions Firestore autour du 15 avril...');
  try {
    const insSnap = await db.collection('megafit_inscriptions')
      .where('gymId', '==', 'dokarat')
      .where('createdAt', '>=', new Date('2026-04-15T00:00:00'))
      .where('createdAt', '<=', new Date('2026-04-15T23:59:59'))
      .limit(20)
      .get();

    if (insSnap.empty) {
      console.log('   Aucune inscription trouvée pour le 15 avril');
    } else {
      insSnap.docs.forEach(d => {
        const e = d.data();
        const total = (Number(e.tpe)||0)+(Number(e.espece)||0)+(Number(e.virement)||0)+(Number(e.cheque)||0);
        console.log(`   ${d.id} | ${e.nom || e.name} | ${total} DH`);
      });
    }
  } catch(e) { console.log('   Erreur:', e.message); }

  // 5. Recherche globale dans le registre de tous les jours proches
  //    pour trouver une entrée de 5900 DH peut-être saisie au mauvais jour
  console.log('\n🔍 5. Entrées de 5,900 DH dans le registre Firestore DOKARAT (14-17 avril)...');
  const daysToCheck = ['2026-04-14', '2026-04-15', '2026-04-16', '2026-04-17'];
  for (const d of daysToCheck) {
    const snap = await db.collection('megafit_daily_register')
      .doc(`dokarat_${d}`)
      .collection('entries')
      .get();
    snap.docs.forEach(doc => {
      const e = doc.data();
      const total = (Number(e.tpe)||0)+(Number(e.espece)||0)+(Number(e.virement)||0)+(Number(e.cheque)||0);
      if (total === 5900) {
        console.log(`   ✅ TROUVÉ  ${d} | ${doc.id} | ${e.nom} | ${e.commercial} | ${total} DH`);
      }
    });
  }

  // 6. Summary
  console.log('\n══════════════════════════════════════════════════════════════════');
  console.log('CONCLUSION :');
  console.log('  Firestore 15 avril  = 11,650 DH');
  console.log('  Excel attendu       = 17,550 DH');
  console.log('  Manquant            =  5,900 DH');
  console.log('\n  → Si ce membre n\'est pas dans la liste ci-dessus,');
  console.log('    le paiement n\'a jamais été saisi dans le dashboard.');
  console.log('    Il faut l\'ajouter manuellement dans le registre du 15 avril.\n');

  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
