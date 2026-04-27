const fs = require('fs');
const db = require('better-sqlite3')('megafit_cache.db');

// 1. Load all Odoo members from the CSV
const csv = fs.readFileSync('../odoo/all_members_all_clubs.csv', 'utf8');
const lines = csv.split('\n').slice(1); // skip header

const odooMembers = lines
  .filter(l => l.trim())
  .map(l => {
    const parts = l.split(',');
    return {
      fullName: (parts[0] || '').trim().toUpperCase(),
      firstname: (parts[1] || '').trim().toUpperCase(),
      lastname: (parts[2] || '').trim().toUpperCase(),
      phone: (parts[4] || '').trim(),
      club: (parts[6] || '').trim().toUpperCase(),
      status: (parts[7] || '').trim()
    };
  })
  .filter(m => m.fullName);

// Build lookup sets (normalized)
const normalize = s => s.replace(/\s+/g, ' ').trim().toUpperCase();
const odooNameSet = new Set(odooMembers.map(m => normalize(m.fullName)));
// Also add individual parts (lastname only) for partial match
const odooLastnames = new Set(odooMembers.map(m => normalize(m.lastname)).filter(s => s.length > 2));

// 2. Get all unique door entry names for Doukkarate this month
const entryNames = db.prepare(`
  SELECT DISTINCT name, COUNT(*) as visits, MAX(date) as last_visit
  FROM entries
  WHERE gym_id = 'dokarat' AND date >= '2026-04-01'
    AND name NOT LIKE '%employee%'
    AND name NOT LIKE '%employe%'
    AND name NOT LIKE '%caissier%'
    AND name NOT LIKE '%manager%'
    AND name NOT LIKE '%coach%'
  GROUP BY name
  ORDER BY visits DESC
`).all();

// 3. Cross-reference
const found = [];
const notFound = [];

for (const entry of entryNames) {
  const normalizedEntry = normalize(entry.name || '');
  
  // Try exact match first
  let match = odooMembers.find(m => normalize(m.fullName) === normalizedEntry);
  
  // Try partial: entry name is contained in odoo full name
  if (!match) {
    match = odooMembers.find(m => 
      normalize(m.fullName).includes(normalizedEntry) || 
      normalizedEntry.includes(normalize(m.lastname)) && normalize(m.lastname).length > 3
    );
  }
  
  if (match) {
    found.push({
      doorName: entry.name,
      visits: entry.visits,
      lastVisit: entry.last_visit,
      odooName: match.fullName,
      odooClub: match.club,
      odooStatus: match.status,
      odooPhone: match.phone,
      matchType: normalize(match.fullName) === normalizedEntry ? 'EXACT' : 'PARTIAL'
    });
  } else {
    notFound.push({
      doorName: entry.name,
      visits: entry.visits,
      lastVisit: entry.last_visit
    });
  }
}

// 4. Save results
const foundCsv = ['DoorName,Visits,LastVisit,OdooName,Club,Status,Phone,MatchType'];
found.forEach(r => {
  foundCsv.push([r.doorName, r.visits, r.lastVisit, r.odooName, r.odooClub, r.odooStatus, r.odooPhone, r.matchType].join(','));
});
fs.writeFileSync('cross_reference_FOUND.csv', foundCsv.join('\n'), 'utf8');

const notFoundCsv = ['DoorName,Visits,LastVisit'];
notFound.forEach(r => {
  notFoundCsv.push([r.doorName, r.visits, r.lastVisit].join(','));
});
fs.writeFileSync('cross_reference_NOT_FOUND.csv', notFoundCsv.join('\n'), 'utf8');

console.log('=== CROSS-REFERENCE RESULTS ===');
console.log(`Total unique door entries: ${entryNames.length}`);
console.log(`✅ Found in Odoo: ${found.length} (${Math.round(found.length/entryNames.length*100)}%)`);
console.log(`❌ NOT in Odoo: ${notFound.length} (${Math.round(notFound.length/entryNames.length*100)}%)`);
console.log('');
console.log('Files saved:');
console.log('  → cross_reference_FOUND.csv');
console.log('  → cross_reference_NOT_FOUND.csv');
