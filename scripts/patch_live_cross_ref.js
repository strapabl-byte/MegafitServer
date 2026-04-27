const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../routes/analytics.js');
let code = fs.readFileSync(file, 'utf8');

// Find the live-entries route start
const startMarker = "router.get('/api/live-entries', verifyAzureToken, (req, res) => {";
const startIdx = code.indexOf(startMarker);
if (startIdx === -1) { console.error('Cannot find start marker'); process.exit(1); }

// Find the end: the closing }); after the route
let depth = 0;
let i = startIdx;
while (i < code.length) {
  if (code[i] === '{') depth++;
  else if (code[i] === '}') { depth--; if (depth === 0) { i++; break; } }
  i++;
}
// skip ); after the }
if (code.slice(i, i+2) === ');') i += 2;
const oldRoute = code.slice(startIdx, i);

const NEW_ROUTE = `router.get('/api/live-entries', verifyAzureToken, (req, res) => {
    try {
      const { gymId, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      const limitCount = Math.min(parseInt(limitParam) || 50, 200);
      const today = getMoroccanDateStr();
      const targetGymIds = gymId === 'all' ? Object.keys(GYM_DOOR_MAP) : [gymId];

      // Cross-reference: load members from SQLite
      const placeholders = targetGymIds.map(() => '?').join(',');
      const memberRows = lc.db.prepare(
        \`SELECT full_name, expires_on FROM members_cache WHERE gym_id IN (\${placeholders})\`
      ).all(...targetGymIds);

      const normalize = s => (s || '').replace(/\\s+/g, ' ').trim().toUpperCase();
      const memberMap = new Map();
      for (const m of memberRows) {
        const key = normalize(m.full_name);
        if (key) memberMap.set(key, { expiresOn: m.expires_on });
      }

      const isSubActive = (expiresOn) => {
        if (!expiresOn) return false;
        try { return new Date(expiresOn) >= new Date(today); } catch (e) { return false; }
      };

      let merged = [];
      targetGymIds.forEach(gid => {
        lc.getEntries(gid, today, limitCount).forEach(e => {
          const entryNorm = normalize(e.name);
          let member = memberMap.get(entryNorm);

          // Partial match: first word of entry = first word of member name
          if (!member && entryNorm.length > 3) {
            const entryFirst = entryNorm.split(' ')[0];
            for (const [mName, mData] of memberMap.entries()) {
              if (mName.includes(entryNorm) || (entryFirst.length > 3 && mName.startsWith(entryFirst))) {
                member = mData;
                break;
              }
            }
          }

          const isKnown = !!member;
          const memberStatus = isKnown
            ? (isSubActive(member.expiresOn) ? 'active' : 'expired')
            : 'unknown';

          merged.push({
            docId: e.id,
            name: e.name,
            gymId: gid,
            displayTime: (e.timestamp || '').slice(11, 16),
            timestamp: e.timestamp,
            status: e.status,
            method: e.method,
            isFace: e.is_face === 1,
            isKnown,
            memberStatus,
            expiresOn: member ? member.expiresOn : null,
          });
        });
      });

      merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      res.json({ ok: true, gymId, count: merged.length, entries: merged.slice(0, limitCount) });
    } catch (err) {
      console.error('Live Entries Error:', err);
      res.status(500).json({ error: 'Failed to fetch live entries' });
    }
  });`;

code = code.replace(oldRoute, NEW_ROUTE);
fs.writeFileSync(file, code, 'utf8');
console.log('✅ analytics.js patched - live-entries now cross-references members');
console.log('Old route length:', oldRoute.length, 'chars');
