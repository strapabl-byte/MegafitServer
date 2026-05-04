const DB = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const CORRECTED_CSV = 'c:\\Users\\Thatsme\\Documents\\MegaSolution\\odoo\\auralix_dashboard_export_REBUILT_corrected.csv';
const DB_PATH = 'c:\\Users\\Thatsme\\Documents\\MegaSolution\\megafit-api\\megafit_cache.db';

function cleanVal(v) {
  if (!v) return '';
  return v.trim().replace(/^"|"$/g, '').trim();
}

console.log('Reading corrected CSV...');
const content = fs.readFileSync(CORRECTED_CSV, 'utf8');
const lines = content.split('\n').filter(l => l.trim());
const headers = lines[0].split(',');

// Map header indices with cleaning
const idx = {};
headers.forEach((h, i) => {
  const cleanH = h.trim().replace(/^\uFEFF/, '').toUpperCase();
  idx[cleanH] = i;
});

const db = new DB(DB_PATH);

console.log('Starting DB update...');
let updatedCount = 0;
let notFoundCount = 0;

db.transaction(() => {
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    const cols = line.split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/); 
    const date = cleanVal(cols[idx['DATE']]);
    const nom = cleanVal(cols[idx['NOM']]);
    const correctedResult = cleanVal(cols[idx['CORRECTED_RESULT']]);
    const confidence = parseInt(cleanVal(cols[idx['MATCH_CONFIDENCE']])) || 0;
    const matchedName = cleanVal(cols[idx['MATCHED_FULL_NAME']]);
    const matchedClub = cleanVal(cols[idx['MATCHED_CLUB']]);
    const matchedStatus = cleanVal(cols[idx['MATCHED_STATUS']]);
    const subStop = cleanVal(cols[idx['SUBS_STOP']]);
    const logic = cleanVal(cols[idx['MATCH_LOGIC']]);
    const note = cleanVal(cols[idx['REVIEW_NOTE']]);

    // Find the register_id - try exact then trimmed
    let row = db.prepare('SELECT id FROM register_cache WHERE nom = ? AND date = ?').get(nom, date);
    if (!row) {
      // Try fuzzy match if exact fails (e.g. whitespace differences)
      row = db.prepare('SELECT id FROM register_cache WHERE TRIM(nom) = ? AND date = ?').get(nom.trim(), date);
    }
    
    if (row) {
      let type = 'NEW';
      if (correctedResult === 'FOUND') type = 'RESUB';
      else if (correctedResult === 'REVIEW') type = 'POSSIBLE';

      const reason = `Audit Rebuilt: ${logic} | ${note}`;

      db.prepare(`
        INSERT OR REPLACE INTO resub_intelligence_cache
        (register_id, gym_id, nom_key, type, confidence, matched_name,
         prev_club, prev_status, last_sub, ai_verified,
         ai_reason, detection_mode, cached_at)
        SELECT 
          ?, gym_id, ?, ?, ?, ?,
          ?, ?, ?, 1,
          ?, 'AURALIX', ?
        FROM register_cache WHERE id = ?
      `).run(
        row.id, 
        nom.trim().toUpperCase(), 
        type, 
        confidence, 
        matchedName || null,
        matchedClub || null,
        matchedStatus || null,
        subStop || null,
        reason,
        new Date().toISOString(),
        row.id
      );
      updatedCount++;
    } else {
      notFoundCount++;
    }
  }
})();

console.log(`✅ Update complete!`);
console.log(`Updated: ${updatedCount}`);
console.log(`Not found in DB: ${notFoundCount}`);
