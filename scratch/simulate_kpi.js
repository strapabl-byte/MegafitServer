const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'megafit_cache.db');
const db = new Database(dbPath);

const lc = {
  db,
  getRegister: (gymId, date) => {
    const sql = `SELECT * FROM register_cache WHERE gym_id = ? AND date=? ORDER BY created_at DESC`;
    return db.prepare(sql).all(gymId, date);
  },
  getDecaissements: (gymId, date) => {
    const sql = `SELECT * FROM decaissements_cache WHERE gym_id = ? AND date=? ORDER BY created_at ASC`;
    return db.prepare(sql).all(gymId, date);
  }
};

const getRevenueAndBreakdown = (fromDate, now, gymIds) => {
  let total = 0, espece = 0, tpe = 0, virement = 0, cheque = 0;
  const cursor = new Date(fromDate);
  
  const toLocalDateStr = (d) => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  
  while (cursor <= now) {
    const dateStr = toLocalDateStr(cursor);
    for (const gid of gymIds) {
      lc.getRegister(gid, dateStr).forEach(e => {
        const e_esp = Number(e.espece) || 0;
        const e_tpe = Number(e.tpe) || 0;
        const e_vir = Number(e.virement) || 0;
        const e_che = Number(e.cheque) || 0;
        espece += e_esp; tpe += e_tpe; virement += e_vir; cheque += e_che;
        total += e_esp + e_tpe + e_vir + e_che;
      });
      const decs = lc.getDecaissements(gid, dateStr);
      if (decs) {
        decs.forEach(dec => {
          const amt = Number(dec.montant) || 0;
          espece -= amt;
          total -= amt;
        });
      }
    }
    cursor.setDate(cursor.getDate() + 1);
  }
  return { total, espece, tpe, virement, cheque };
};

const now = new Date('2026-05-19');
const monthStart = new Date('2026-05-01');

console.log('Simulating monthly KPI for casa1:');
console.log(getRevenueAndBreakdown(monthStart, now, ['casa1']));
