// patch_live_entries.js — Node.js script to patch analytics.js + server.js
const fs = require('fs');
const path = require('path');

// ── analytics.js ──────────────────────────────────────────────────────────────
const analyticsPath = path.join(__dirname, 'routes', 'analytics.js');
let analytics = fs.readFileSync(analyticsPath, 'utf8');

// 1. Replace the async route handler with a synchronous SQLite-only one
const OLD_ROUTE = `router.get('/api/live-entries', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, limit: limitParam } = req.query;
      if (!gymId) return res.status(400).json({ error: 'gymId required' });
      const limitCount = Math.min(parseInt(limitParam) || 50, 200);
      const today = getMoroccanDateStr();
      const targetGymIds = gymId === 'all' ? Object.keys(GYM_DOOR_MAP) : [gymId];

      await Promise.all(targetGymIds.map(async (gid) => {
        const g = GYM_DOOR_MAP[gid];
        if (!g) return;
        const FETCH_MIN_GAP_MS = 12000;
        const lastSyncKey      = \`liveEntries_sync_\${gid}\`;
        const lastSyncTime     = parseInt(lc.getMeta(lastSyncKey) || '0');
        const existingEntries  = lc.getEntries(gid, today, 100);
        const lastTimestamp    = existingEntries.length > 0 ? existingEntries.reduce((max, e) => e.timestamp > max ? e.timestamp : max, '') : null;

        if (!lastTimestamp || Date.now() - lastSyncTime >= FETCH_MIN_GAP_MS) {
          try {
            const newEntries = [];
            for (const coll of g.collections) {
              const body = { structuredQuery: { from: [{ collectionId: coll }], where: { fieldFilter: { field: { fieldPath: 'timestamp' }, op: lastTimestamp ? 'GREATER_THAN' : 'GREATER_THAN_OR_EQUAL', value: { stringValue: lastTimestamp || today } } }, orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'ASCENDING' }], limit: 200 } };
              const resp = await fetch(DOOR_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
              const data = await resp.json();
              if (!Array.isArray(data)) continue;
              data.filter(d => d.document).forEach(d => {
                const f  = d.document.fields || {};
                const ts = f.timestamp?.stringValue || '';
                if (!ts.startsWith(today)) return;
                const loc  = (f.location?.stringValue || '').toLowerCase();
                const tags = g.locationTags.map(t => t.toLowerCase());
                if (!tags.some(t => loc.includes(t) || t.includes(loc))) return;`;

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
  });`;

// Find the old route block — match up to the closing }); of the route
const oldRouteStart = analytics.indexOf("router.get('/api/live-entries', verifyAzureToken, async");
if (oldRouteStart === -1) {
  console.error('Could not find old live-entries route');
  process.exit(1);
}
// Find the closing `  });` of the route (2 spaces + }); followed by newline + newline)
let closeIdx = analytics.indexOf('\n  });\n\n  //', oldRouteStart);
if (closeIdx === -1) closeIdx = analytics.indexOf('\n  });\n\n', oldRouteStart);
const oldRouteEnd = closeIdx + '\n  });'.length;
analytics = analytics.slice(0, oldRouteStart) + NEW_ROUTE + analytics.slice(oldRouteEnd);
console.log('✅ live-entries route replaced (SQLite-only)');

// 2. Inject pollDoorEntries function before `return router;`
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
              status: f.status?.stringValue || 'Entree',
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

const returnIdx = analytics.lastIndexOf('  return router;\n};');
if (returnIdx === -1) {
  console.error('Could not find return router');
  process.exit(1);
}
analytics = analytics.slice(0, returnIdx) + POLL_FN + analytics.slice(returnIdx);
console.log('✅ pollDoorEntries injected');

fs.writeFileSync(analyticsPath, analytics, 'utf8');

// Quick syntax check
try {
  require('./routes/analytics');
  console.log('✅ analytics.js syntax OK');
} catch (e) {
  console.error('❌ Syntax error in analytics.js:', e.message);
  process.exit(1);
}

// ── server.js ──────────────────────────────────────────────────────────────────
const serverPath = path.join(__dirname, 'server.js');
let server = fs.readFileSync(serverPath, 'utf8');

// a) Replace the analytics router mount to capture the instance
const OLD_MOUNT = "app.use('/',                require('./routes/analytics')(deps));   // /api/live-entries, /api/live-count, /api/analytics/*, /api/admin/sync-stats";
const NEW_MOUNT = `// analytics router — stored so we can call pollDoorEntries() from the interval
const analyticsRouter = require('./routes/analytics')(deps);
app.use('/', analyticsRouter); // mounts /api/live-entries, /api/live-count, /api/analytics/*`;

if (!server.includes(OLD_MOUNT)) {
  console.error('Could not find analytics mount line in server.js — attempting partial match');
  // Try shorter match
  const SHORT = "require('./routes/analytics')(deps)";
  if (!server.includes(SHORT)) {
    console.error('Could not find analytics require at all');
    process.exit(1);
  }
}
server = server.includes(OLD_MOUNT) ? server.replace(OLD_MOUNT, NEW_MOUNT) : server;
console.log('✅ analyticsRouter variable created');

// b) Add 60s poll interval after scheduleNightlySync
const OLD_SCHEDULE = '  scheduleNightlySync(db, apiCache, isQuotaExceeded);';
const NEW_SCHEDULE = `  scheduleNightlySync(db, apiCache, isQuotaExceeded);

  // ── Server-side door entries poll (60s) ───────────────────────────────────────
  // Replaces per-request Firestore calls. One poll = all clients served from SQLite.
  async function runDoorPoll() {
    if (isQuotaExceeded()) return;
    try { await analyticsRouter.pollDoorEntries(); }
    catch (e) { console.warn('[DOOR POLL] error:', e.message); }
  }
  setTimeout(runDoorPoll, 5000);        // first poll 5s after startup (warm SQLite)
  setInterval(runDoorPoll, 60 * 1000); // then every 60 seconds`;

if (!server.includes(OLD_SCHEDULE)) {
  console.error('Could not find scheduleNightlySync line in server.js');
  process.exit(1);
}
server = server.replace(OLD_SCHEDULE, NEW_SCHEDULE);
console.log('✅ 60s door poll interval added to server.js');

fs.writeFileSync(serverPath, server, 'utf8');
console.log('✅ All patches applied successfully');
