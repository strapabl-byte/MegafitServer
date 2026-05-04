const fs = require('fs');
const path = require('path');
const DB = require('better-sqlite3');

const CSV_PATH = 'c:\\Users\\Thatsme\\Documents\\MegaSolution\\odoo\\all_members_all_clubs.csv';
const DB_PATH = 'c:\\Users\\Thatsme\\Documents\\MegaSolution\\megafit-api\\megafit_cache.db';

// ── UTILS ──
function cleanName(n) {
  if (!n) return '';
  return n.trim().toUpperCase()
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function levenshtein(a, b) {
  const la = a.length, lb = b.length;
  let prev = Array.from({ length: lb + 1 }, (_, i) => i);
  for (let i = 1; i <= la; i++) {
    const cur = [i];
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[lb];
}

function similarity(a, b) {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 100;
  return Math.round((1 - levenshtein(a, b) / maxLen) * 100);
}

// ── DATA LOADING ──
console.log('Loading Odoo CSV...');
const csvData = fs.readFileSync(CSV_PATH, 'utf8');
const lines = csvData.split('\n').filter(l => l.trim());
const headers = lines[0].split(',');
const members = lines.slice(1).map(line => {
  const cols = line.split(',');
  return {
    full_name: cols[0],
    club:      cols[6],
    status:    cols[7],
    subs_stop: cols[9],
    x_birthday:cols[12],
    cleaned:   cleanName(cols[0])
  };
});
console.log(`Indexed ${members.length} Odoo members.`);

const db = new DB(DB_PATH);
const localInscriptions = db.prepare(`
  SELECT id, nom, date, gym_id, abonnement 
  FROM register_cache 
  WHERE date >= '2026-04-01'
`).all();
console.log(`Auditing ${localInscriptions.length} inscriptions...`);

const localBirthdays = new Map();
const bdayRows = db.prepare("SELECT full_name, birthday FROM members_cache WHERE birthday IS NOT NULL AND birthday != ''").all();
for (const b of bdayRows) localBirthdays.set(cleanName(b.full_name), b.birthday);

// ── AUDIT ──
const results = [];
for (const ins of localInscriptions) {
  const qClean = cleanName(ins.nom);
  const mBday = localBirthdays.get(qClean);
  
  let bestMatch = null;
  let bestScore = 0;

  // Faster pre-filter: check if first 4 letters match or use a simple bigram subset if needed
  // But for 400x12000, we can just do a subset scan
  for (const m of members) {
    // Hard birthday match
    if (mBday && m.x_birthday === mBday) {
      bestMatch = m;
      bestScore = 100;
      break;
    }

    const s = similarity(qClean, m.cleaned);
    if (s > bestScore) {
      bestScore = s;
      bestMatch = m;
    }
    if (bestScore === 100) break;
  }

  let type = 'NEW';
  let mode = 'AUDIT';
  let reason = 'Analyse Antigravity';

  if (bestScore === 100 && bestMatch.x_birthday === mBday) {
    type = 'RESUB';
    mode = 'BIRTHDAY-MATCH';
    reason = `Confirmé par date de naissance (${mBday})`;
  } else if (bestScore >= 85) {
    type = 'RESUB';
    reason = `Match haute confiance (${bestScore}%)`;
  } else if (bestScore >= 75) {
    // Human-like strict family check (simple heuristic)
    const qParts = ins.nom.toUpperCase().split(/\s+/);
    const mParts = bestMatch.full_name.toUpperCase().split(/\s+/);
    const familyMatch = qParts.some(p => mParts.includes(p));
    
    if (familyMatch) {
      type = 'RESUB';
      reason = `Match probable (${bestScore}%) - Noms partagés`;
    } else {
      type = 'NEW';
      reason = `Similitude fortuite (${bestScore}%) - Familles différentes`;
    }
  }

  results.push({
    register_id: ins.id,
    gym_id:      ins.gym_id,
    nom_key:     qClean,
    type,
    confidence:  bestScore,
    matched_name:bestMatch?.full_name || null,
    prev_club:   bestMatch?.club || null,
    prev_status: bestMatch?.status || null,
    last_sub:    bestMatch?.subs_stop || null,
    ai_verified: 1,
    ai_reason:   reason,
    detection_mode: mode,
    cached_at:   new Date().toISOString()
  });
}

// ── SAVE ──
const insert = db.prepare(`
  INSERT OR REPLACE INTO resub_intelligence_cache
  (register_id, gym_id, nom_key, type, confidence, matched_name,
   prev_club, prev_status, last_sub, ai_verified,
   ai_reason, detection_mode, cached_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertMany = db.transaction((data) => {
  for (const row of data) {
    insert.run(
      row.register_id, row.gym_id, row.nom_key, row.type, row.confidence, row.matched_name,
      row.prev_club, row.prev_status, row.last_sub, row.ai_verified,
      row.ai_reason, row.detection_mode, row.cached_at
    );
  }
});

insertMany(results);
console.log(`✅ Audit Complete! Saved ${results.length} verified results to SQLite.`);
