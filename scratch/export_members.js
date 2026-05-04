const DB = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const db = new DB('megafit_cache.db');
const rows = db.prepare(`
  SELECT 
    r.date, 
    r.gym_id, 
    r.nom, 
    r.abonnement, 
    r.prix, 
    i.type AS auralix_verdict, 
    i.confidence AS auralix_confidence, 
    i.matched_name AS matched_odoo_name,
    i.ai_reason AS auralix_reason
  FROM register_cache r
  LEFT JOIN resub_intelligence_cache i ON r.id = i.register_id
  ORDER BY r.date DESC
`).all();

const header = 'DATE,GYM,NOM,ABONNEMENT,PRIX,AURALIX_VERDICT,CONFIDENCE,MATCHED_ODOO_NAME,REASON\n';
const csv = header + rows.map(r => {
  return [
    r.date,
    r.gym_id,
    `"${(r.nom || '').replace(/"/g, '""')}"`,
    `"${(r.abonnement || '').replace(/"/g, '""')}"`,
    r.prix,
    r.auralix_verdict || '—',
    r.auralix_confidence || 0,
    `"${(r.matched_odoo_name || '').replace(/"/g, '""')}"`,
    `"${(r.auralix_reason || '').replace(/"/g, '""')}"`
  ].join(',');
}).join('\n');

const exportPath = path.join(__dirname, '..', 'auralix_dashboard_export.csv');
fs.writeFileSync(exportPath, csv);
console.log(`Successfully exported ${rows.length} records to ${exportPath}`);
