
# patch_live_entries.ps1
# 1. Replaces the /api/live-entries route (lines 38-90) with a pure SQLite serve
# 2. Adds an exported pollDoorEntries function before `return router`
# 3. Adds the 60s server-side poll to server.js

$analyticsPath = "routes\analytics.js"
$serverPath    = "server.js"

# ── analytics.js ──────────────────────────────────────────────────────────────
$raw = [System.IO.File]::ReadAllText($analyticsPath, [System.Text.Encoding]::UTF8)

$oldRoute = @'
  // ?????? GET /api/live-entries ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
  router.get('/api/live-entries', verifyAzureToken, async (req, res) => {
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
        const lastSyncKey      = `liveEntries_sync_${gid}`;
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
                if (!tags.some(t => loc.includes(t) || t.includes(loc))) return;
                newEntries.push({ id: d.document.name?.split('/').pop() || ts, gym_id: gid, date: today, timestamp: ts, name: f.name?.stringValue || '', method: f.method?.stringValue || '', status: f.status?.stringValue || 'Entr??e', is_face: (f.method?.stringValue || '').toLowerCase().includes('face') ? 1 : 0 });
              });
            }
            if (newEntries.length > 0) lc.upsertEntries(gid, newEntries);
            lc.setMeta(lastSyncKey, String(Date.now()));
          } catch (e) { console.warn(`?????? Sync failed for ${gid}: ${e.message}`); }
        }
      }));

      let merged = [];
      targetGymIds.forEach(gid => {
        lc.getEntries(gid, today, limitCount).forEach(e => merged.push({ docId: e.id, name: e.name, gymId: gid, displayTime: (e.timestamp || '').slice(11, 16), timestamp: e.timestamp, status: e.status, method: e.method, isFace: e.is_face === 1 }));
      });
      merged.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      const final = merged.slice(0, limitCount);
      res.json({ ok: true, gymId, count: final.length, entries: final });
    } catch (err) {
      console.error('Live Entries Error:', err);
      res.status(500).json({ error: 'Failed to fetch live entries' });
    }
  });
'@

$newRoute = @'
  // ── GET /api/live-entries — SQLite only, NO Firestore reads ──────────────────
  // Door entries are synced server-side every 60s via pollDoorEntries()
  // This endpoint just reads from SQLite — instant, zero quota cost.
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
'@

# Find the old route, normalize CRLF for matching
$rawNorm = $raw -replace "`r`n", "`n"
$oldNorm  = $oldRoute.Trim() -replace "`r`n", "`n"
$newNorm  = $newRoute.Trim() -replace "`r`n", "`n"

if ($rawNorm.Contains($oldNorm)) {
    $patched = $rawNorm.Replace($oldNorm, $newNorm)
    Write-Host "Route replacement: SUCCESS"
} else {
    Write-Host "Route replacement: NOT FOUND — trying partial match..."
    # Try matching by the route function signature alone
    $sigOld = "router.get('/api/live-entries', verifyAzureToken, async (req, res) => {"
    $sigNew = "router.get('/api/live-entries', verifyAzureToken, (req, res) => {"
    $patched = $rawNorm
    Write-Host "Falling back to manual edit required"
}

# Now add pollDoorEntries before `return router;`
$pollFn = @'

  // ── pollDoorEntries — called by server.js every 60s ──────────────────────────
  // This is the ONLY place that reads from the door Firebase project.
  // All dashboard clients read from SQLite; this background task keeps it fresh.
  router.pollDoorEntries = async function pollDoorEntries() {
    const today = getMoroccanDateStr();
    for (const [gid, g] of Object.entries(GYM_DOOR_MAP)) {
      try {
        const existingEntries = lc.getEntries(gid, today, 500);
        const lastTimestamp   = existingEntries.length > 0
          ? existingEntries.reduce((max, e) => e.timestamp > max ? e.timestamp : max, '')
          : null;
        const newEntries = [];
        for (const coll of g.collections) {
          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: { fieldFilter: { field: { fieldPath: 'timestamp' }, op: lastTimestamp ? 'GREATER_THAN' : 'GREATER_THAN_OR_EQUAL', value: { stringValue: lastTimestamp || today } } },
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'ASCENDING' }],
              limit: 200,
            }
          };
          const resp = await fetch(DOOR_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
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
              name: f.name?.stringValue || '',
              method: f.method?.stringValue || '',
              status: f.status?.stringValue || 'Entree',
              is_face: (f.method?.stringValue || '').toLowerCase().includes('face') ? 1 : 0,
            });
          });
        }
        if (newEntries.length > 0) {
          lc.upsertEntries(gid, newEntries);
          console.log(`[DOOR POLL] ${gid}: +${newEntries.length} new entries`);
        }
        lc.setMeta(`liveEntries_sync_${gid}`, String(Date.now()));
      } catch (e) {
        console.warn(`[DOOR POLL] ${gid} failed: ${e.message}`);
      }
    }
  };

'@

$pollNorm = $pollFn -replace "`r`n", "`n"
if ($patched.Contains("  return router;`n};")) {
    $patched = $patched.Replace("  return router;`n};", $pollNorm + "  return router;`n};")
    Write-Host "pollDoorEntries injection: SUCCESS"
} else {
    Write-Host "pollDoorEntries injection: could not find 'return router'"
}

[System.IO.File]::WriteAllText($analyticsPath, $patched, [System.Text.Encoding]::UTF8)
Write-Host "analytics.js written: $($patched.Length) chars"

# ── server.js ─────────────────────────────────────────────────────────────────
$srv = [System.IO.File]::ReadAllText($serverPath, [System.Text.Encoding]::UTF8) -replace "`r`n", "`n"

# Find the analytics router mount line and capture it
$analyticsMount = "app.use('/',                require('./routes/analytics')(deps));   // /api/live-entries, /api/live-count, /api/analytics/*, /api/admin/sync-stats"

$newMount = "const analyticsRouter = require('./routes/analytics')(deps);   // /api/live-entries, /api/live-count, /api/analytics/*`napp.use('/', analyticsRouter);"

if ($srv.Contains($analyticsMount)) {
    $srv = $srv.Replace($analyticsMount, $newMount)
    Write-Host "Server mount patch: SUCCESS"
} else {
    Write-Host "Server mount patch: mount line not found exactly, trying fuzzy"
}

# Add the 60s door poll interval after the scheduleNightlySync line
$oldSchedule = "  scheduleNightlySync(db, apiCache, isQuotaExceeded);"
$newSchedule = @"
  scheduleNightlySync(db, apiCache, isQuotaExceeded);

  // ── Door entries background poll — 60s server-side, zero client Firestore reads ──
  async function runDoorPoll() {
    try { await analyticsRouter.pollDoorEntries(); }
    catch (e) { console.warn('[DOOR POLL] interval error:', e.message); }
  }
  setTimeout(runDoorPoll, 5000);           // first poll 5s after startup
  setInterval(runDoorPoll, 60 * 1000);    // then every 60 seconds
"@

$newScheduleNorm = $newSchedule -replace "`r`n", "`n"
if ($srv.Contains($oldSchedule)) {
    $srv = $srv.Replace($oldSchedule, $newScheduleNorm)
    Write-Host "Server interval injection: SUCCESS"
} else {
    Write-Host "Server interval injection: NOT FOUND"
}

[System.IO.File]::WriteAllText($serverPath, $srv, [System.Text.Encoding]::UTF8)
Write-Host "server.js written: $($srv.Length) chars"

# Validate
$result = node -e "try { require('./routes/analytics'); console.log('OK') } catch(e) { console.log('ERR:', e.message) }" 2>&1
Write-Host "Syntax check: $result"
