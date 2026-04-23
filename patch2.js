const fs = require('fs');

let code = fs.readFileSync('routes/analytics.js', 'utf8');

const startIdx = code.indexOf('// ── GET /api/live-entries');
if (startIdx === -1) { console.error('Start comment not found'); process.exit(1); }

// Find the start of the next section
const endIdx = code.indexOf('// ── GET /api/live-count', startIdx);
if (endIdx === -1) { console.error('End comment not found'); process.exit(1); }

const NEW_ROUTE = `// ── GET /api/live-entries — pure SQLite read, zero Firestore calls ──────────
  // Door DB is polled server-side every 60s (see server.js pollDoorEntries).
  // Any number of dashboard clients calling this = always 0 extra reads.
  router.get('/api/live-entries', verifyAzureToken, (req, res) => {
    try {
      const { gymId, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      const limitCount = Math.min(parseInt(limitParam) || 50, 200);
      const today = getMoroccanDateStr();
      const targetGymIds = gymId === 'all' ? Object.keys(GYM_DOOR_MAP) : [gymId];
      let merged = [];
      targetGymIds.forEach(gid => {
        lc.getEntries(gid, today, limitCount).forEach(e => merged.push({
          docId: e.id, name: e.name, gymId: gid,
          displayTime: (e.timestamp || '').slice(11, 16),
          timestamp: e.timestamp, status: e.status,
          method: e.method, isFace: e.is_face === 1,
        }));
      });
      merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      res.json({ ok: true, gymId, count: merged.length, entries: merged.slice(0, limitCount) });
    } catch (err) {
      console.error('Live Entries Error:', err);
      res.status(500).json({ error: 'Failed to fetch live entries' });
    }
  });

  `;

code = code.substring(0, startIdx) + NEW_ROUTE + code.substring(endIdx);

// Now insert pollDoorEntries before 'return router;'
const POLL_FN = `
  // ── pollDoorEntries — server-side background task, called every 60s ──────────
  // This is the ONLY function that talks to the door Firebase project.
  // It incrementally fetches only NEW entries since the last poll.
  router.pollDoorEntries = async function pollDoorEntries() {
    const today = getMoroccanDateStr();
    for (const [gid, g] of Object.entries(GYM_DOOR_MAP)) {
      try {
        const existing      = lc.getEntries(gid, today, 500);
        const lastTimestamp = existing.length > 0
          ? existing.reduce((max, e) => e.timestamp > max ? e.timestamp : max, '')
          : null;
        const newEntries = [];
        for (const coll of g.collections) {
          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: { fieldFilter: {
                field: { fieldPath: 'timestamp' },
                op: lastTimestamp ? 'GREATER_THAN' : 'GREATER_THAN_OR_EQUAL',
                value: { stringValue: lastTimestamp || today }
              }},
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'ASCENDING' }],
              limit: 200,
            }
          };
          const resp = await fetch(DOOR_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          const data = await resp.json();
          if (!Array.isArray(data)) continue;
          data.filter(d => d.document).forEach(d => {
            const f  = d.document.fields || {};
            const ts = f.timestamp?.stringValue || '';
            if (!ts.startsWith(today)) return;
            const loc  = (f.location?.stringValue || '').toLowerCase();
            const tags = g.locationTags.map(t => t.toLowerCase());
            if (!tags.some(t => loc.includes(t) || t.includes(loc))) return;
            newEntries.push({
              id: d.document.name?.split('/').pop() || ts,
              gym_id: gid, date: today, timestamp: ts,
              name:   f.name?.stringValue   || '',
              method: f.method?.stringValue || '',
              status: f.status?.stringValue || 'Entrée',
              is_face: (f.method?.stringValue || '').toLowerCase().includes('face') ? 1 : 0,
            });
          });
        }
        if (newEntries.length > 0) {
          lc.upsertEntries(gid, newEntries);
          console.log(\`[DOOR POLL] \${gid}: +\${newEntries.length} entries\`);
        }
        lc.setMeta(\`liveEntries_sync_\${gid}\`, String(Date.now()));
      } catch (e) {
        console.warn(\`[DOOR POLL] \${gid} failed: \${e.message}\`);
      }
    }
  };

`;

const returnIdx = code.lastIndexOf('  return router;');
if (returnIdx !== -1) {
    code = code.substring(0, returnIdx) + POLL_FN + code.substring(returnIdx);
} else {
    console.error('Could not find return router;'); process.exit(1);
}

fs.writeFileSync('routes/analytics.js', code, 'utf8');
console.log('Successfully patched analytics.js without truncating!');
