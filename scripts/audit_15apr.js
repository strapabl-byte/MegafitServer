/**
 * audit_15apr.js
 * ───────────────
 * Affiche toutes les entrées Firestore du 15 avril 2026 pour DOKARAT.
 * Total Firestore = 11,650 DH vs Excel = 17,550 DH → écart -5,900 DH
 * On cherche qui manque.
 */

process.env.GOOGLE_APPLICATION_CREDENTIALS = __dirname + '/serviceAccount.json';
const admin = require('firebase-admin');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require('./serviceAccount.json')) });
}
const db = admin.firestore();

async function main() {
  const snap = await db.collection('megafit_daily_register')
    .doc('dokarat_2026-04-15')
    .collection('entries')
    .orderBy('createdAt', 'asc')
    .get();

  console.log('\n╔══════════════════════════════════════════════════════════════════╗');
  console.log('║    REGISTRE FIRESTORE — DOKARAT — 15 AVRIL 2026                 ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  let total = 0;
  console.log(`${'#'.padEnd(3)} ${'ID'.padEnd(28)} ${'Nom'.padEnd(25)} ${'Commercial'.padEnd(14)} ${'TPE'.padStart(7)} ${'Espèce'.padStart(8)} ${'Virt'.padStart(7)} ${'Chq'.padStart(7)} ${'TOTAL'.padStart(8)}`);
  console.log('─'.repeat(115));

  snap.docs.forEach((d, i) => {
    const e = d.data();
    const t = (Number(e.tpe)||0)+(Number(e.espece)||0)+(Number(e.virement)||0)+(Number(e.cheque)||0);
    total += t;
    console.log(`${String(i+1).padEnd(3)} ${d.id.padEnd(28)} ${(e.nom||'').padEnd(25)} ${(e.commercial||'').padEnd(14)} ${String(e.tpe||0).padStart(7)} ${String(e.espece||0).padStart(8)} ${String(e.virement||0).padStart(7)} ${String(e.cheque||0).padStart(7)} ${String(t).padStart(8)} DH`);
  });

  console.log('─'.repeat(115));
  console.log(`${' '.repeat(95)} ${String(total).padStart(8)} DH  ← Firestore total`);
  console.log(`${' '.repeat(95)} ${String(17550).padStart(8)} DH  ← Excel attendu`);
  console.log(`${' '.repeat(95)} ${String(17550 - total).padStart(8)} DH  ← MANQUANT`);
  console.log(`\n→ Il faudrait une entrée de ${17550 - total} DH non saisie dans Firestore.\n`);
}

main().catch(e => { console.error(e.message); process.exit(1); });
