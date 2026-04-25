const db = require('better-sqlite3')('./megafit_cache.db');

// Résultats provenant du fichier Excel (Jours 1 à 24)
const excelData = {
  'HAJAR': 361650,
  'OUISSALE': 357200,
  'IMANE': 36850,
};

// Requête pour récupérer les données depuis le Registre SQLite (Dokarat, Avril 2026)
const rows = db.prepare(`
  SELECT
    UPPER(TRIM(commercial)) AS raw_name,
    SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) AS revenue
  FROM register_cache
  WHERE gym_id = 'dokarat' AND date LIKE '2026-04%'
  GROUP BY UPPER(TRIM(commercial))
`).all();

// Normalisation des noms pour le Registre
const registerData = {};
function normalizeName(name) {
  let up = (name || '').trim().toUpperCase();
  if (up.startsWith('HAJAR')) return 'HAJAR';
  if (up === 'OUISSAL' || up === 'OUISSALE' || up === 'OISSALE' || up === 'OUISSALL') return 'OUISSALE';
  if (up === 'IMAN' || up === 'IMANE') return 'IMANE';
  
  // Pour tous les autres commerciaux système, tirets, etc.
  if (!up || up === '-' || up === 'NULL' || up.includes('@') || up.startsWith('MR') || ['OFFERT','GRATUIT','TEST','SYSTEM'].includes(up)) {
    return 'AUTRE (SANS NOM)';
  }
  return up;
}

rows.forEach(r => {
  const name = normalizeName(r.raw_name);
  if (!registerData[name]) registerData[name] = 0;
  registerData[name] += Number(r.revenue || 0);
});

console.log('| Commercial | CA EXCEL (Jours 1-24) | CA REGISTRE APP (Avril) | Différence |');
console.log('| :--- | :--- | :--- | :--- |');

const allNames = new Set([...Object.keys(excelData), ...Object.keys(registerData)]);
let totalExcel = 0;
let totalRegister = 0;

allNames.forEach(name => {
  if (name === 'AUTRE (SANS NOM)' && !registerData[name]) return; // Ignorer si 0
  
  const excelRev = excelData[name] || 0;
  const regRev = registerData[name] || 0;
  const diff = regRev - excelRev;
  
  let diffStr = diff === 0 ? '✅ Parfait (0 DH)' : (diff > 0 ? `+${diff.toLocaleString()} DH (Registre a plus)` : `${diff.toLocaleString()} DH (Excel a plus)`);
  
  console.log(`| **${name}** | ${excelRev.toLocaleString()} DH | ${regRev.toLocaleString()} DH | ${diffStr} |`);
  
  totalExcel += excelRev;
  totalRegister += regRev;
});

console.log(`| **TOTAL GLOBAL** | **${totalExcel.toLocaleString()} DH** | **${totalRegister.toLocaleString()} DH** | **${(totalRegister - totalExcel).toLocaleString()} DH** |`);
