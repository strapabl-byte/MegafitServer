const lc = require('../localCache');

// Helper to get dates for the last 7 days
function getLast7Days() {
  const dates = [];
  const base = new Date('2026-05-24T12:00:00+02:00'); // current mock local time is May 24, 2026
  for (let i = 0; i < 7; i++) {
    const d = new Date(base.getTime() - i * 24 * 60 * 60 * 1000);
    dates.push(d.toISOString().slice(0, 10));
  }
  return dates.reverse();
}

const dates = getLast7Days();
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

  // Let's gather register entries for each date
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

console.log('\n--- COMPARISON RESULTS ---');
console.table(results);
