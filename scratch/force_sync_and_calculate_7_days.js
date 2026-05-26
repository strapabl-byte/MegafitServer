const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');
const { syncGymCounts } = require('../auto_sync');
const lc = require('../localCache');

// Initialize Firebase Admin SDK if not already initialized
if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function run() {
  console.log('Starting force sync for last 7 days...');
  // Sync the last 7 days (daysBack = 7), register only
  await syncGymCounts(db, {}, 7, () => false, true, { syncRegisterOnly: true });
  console.log('Sync completed! Calculating revenues...');

  // Get dates for the last 7 days ending May 24, 2026
  const dates = [];
  const base = new Date('2026-05-24T12:00:00+02:00');
  for (let i = 0; i < 7; i++) {
    const d = new Date(base.getTime() - i * 24 * 60 * 60 * 1000);
    dates.push(d.toISOString().slice(0, 10));
  }
  dates.reverse();

  console.log('Date range (last 7 days):', dates[0], 'to', dates[dates.length - 1]);

  const gyms = ['dokarat', 'marjane', 'casa1', 'casa2'];
  const gymNames = {
    dokarat: 'Dokarat (Fès)',
    marjane: 'Fès Saïss',
    casa1: 'Casa Anfa',
    casa2: 'Lady Anfa'
  };

  const results = {};

  gyms.forEach(gid => {
    let gross = 0;
    let decApproved = 0;
    let decAllExceptRejected = 0;

    dates.forEach(d => {
      // Gross revenue
      const registerEntries = lc.getRegister(gid, d) || [];
      registerEntries.forEach(e => {
        const paid = (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
        gross += paid;
      });

      // Decaissements
      const decs = lc.getDecaissements(gid, d) || [];
      decs.forEach(dec => {
        const amt = Number(dec.montant) || 0;
        if (dec.status === 'approved') {
          decApproved += amt;
        }
        if (dec.status !== 'rejected') {
          decAllExceptRejected += amt;
        }
      });
    });

    results[gid] = {
      name: gymNames[gid],
      gross,
      decApproved,
      decAllExceptRejected,
      netCurrent: gross - decApproved,
      netProposed: gross - decAllExceptRejected
    };
  });

  console.log('\n--- REAL SYNCED COMPARISON RESULTS ---');
  console.table(results);
}

run().catch(console.error);
