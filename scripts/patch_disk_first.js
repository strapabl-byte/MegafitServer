/**
 * patch_disk_first.js
 *
 * Upgrades the door entry system to be "disk-first":
 *   1. pollDoorEntries  — now fetches last 20 entries per 60s poll (not just 1)
 *                         so all scans are saved to SQLite disk immediately
 *   2. gapFillDoorEntries — new function exported and called on startup.
 *                           Detects days with 0 count in last 30 days and
 *                           refills them from Firestore. After this, even if
 *                           Firebase goes read=false, all historical data is
 *                           safe on disk.
 */
const fs = require('fs');
const path = require('path');

const analyticsFile = path.join(__dirname, '../routes/analytics.js');
let code = fs.readFileSync(analyticsFile, 'utf8');

// ── 1. Replace pollDoorEntries ───────────────────────────────────────────────
// Find by the marker comment
const POLL_START_MARKER = 'router.pollDoorEntries = async function pollDoorEntries() {';
const POLL_START = code.indexOf(POLL_START_MARKER);
if (POLL_START === -1) { console.error('Cannot find pollDoorEntries start'); process.exit(1); }

// Find the closing }; of that function
let depth = 0, i = POLL_START;
let inFunc = false;
while (i < code.length) {
  if (code[i] === '{') { depth++; inFunc = true; }
  else if (code[i] === '}') {
    depth--;
    if (inFunc && depth === 0) { i++; break; }
  }
  i++;
}
// skip ;\n after }
while (i < code.length && (code[i] === ';' || code[i] === '\r' || code[i] === '\n')) i++;
const POLL_OLD = code.slice(POLL_START, i);

const POLL_NEW = `router.pollDoorEntries = async function pollDoorEntries() {
    const today = getMoroccanDateStr();
    const nextDay = new Date(new Date(today).getTime() + 86400000).toISOString().slice(0, 10);

    for (const [gid, g] of Object.entries(GYM_DOOR_MAP)) {
      try {
        let bestUnique = 0;
        let bestTotal  = 0;

        for (const coll of g.collections) {
          // Fetch last 20 entries for today (disk-first: save ALL scans, not just count)
          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: {
                compositeFilter: {
                  op: 'AND',
                  filters: [
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: today } } },
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'LESS_THAN', value: { stringValue: nextDay } } }
                  ]
                }
              },
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
              limit: 20,   // ✅ Save all recent entries to disk (not just 1)
            }
          };

          const resp = await fetch(DOOR_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          if (!resp.ok) { console.warn(\`[DOOR POLL] \${gid}/\${coll} HTTP \${resp.status}\`); continue; }
          const data = await resp.json();
          if (!Array.isArray(data)) continue;

          const docs = data.filter(item => item.document).map(item => item.document);
          if (!docs.length) continue;

          for (const doc of docs) {
            const f   = doc.fields || {};
            const loc = (f.location?.stringValue || '').toLowerCase();
            const tags = g.locationTags.map(t => t.toLowerCase());
            if (!tags.some(t => loc.includes(t) || t.includes(loc))) continue;

            // Read device-embedded daily totals from every doc (most accurate on the last one)
            const du = f.daily_unique?.integerValue != null ? parseInt(f.daily_unique.integerValue) :
                       f.daily_unique?.doubleValue  != null ? Math.round(f.daily_unique.doubleValue) : 0;
            const dt = f.daily_total?.integerValue  != null ? parseInt(f.daily_total.integerValue) :
                       f.daily_total?.doubleValue   != null ? Math.round(f.daily_total.doubleValue) : 0;
            if (du > bestUnique) { bestUnique = du; bestTotal = dt; }

            // ✅ Save every entry to disk (live feed + offline backup)
            const ts = f.timestamp?.stringValue || '';
            if (ts.startsWith(today)) {
              const entryId = doc.name?.split('/').pop() || ts;
              lc.upsertEntries(gid, [{
                id:        entryId,
                gym_id:    gid,
                date:      today,
                timestamp: ts,
                name:      f.name?.stringValue   || '',
                method:    f.method?.stringValue || '',
                status:    f.status?.stringValue || 'Entrée',
                is_face:   (f.method?.stringValue || '').toLowerCase().includes('face') ? 1 : 0,
              }]);
            }
          }
        }

        if (bestUnique > 0) {
          const prev = lc.getDailyStat(gid, today)?.count || 0;
          lc.upsertDailyStat(gid, today, bestUnique, bestTotal);
          if (bestUnique !== prev) {
            console.log(\`[DOOR POLL] \${gid}: \${bestUnique} unique / \${bestTotal} total today\`);
          }
        }

        lc.setMeta(\`liveEntries_sync_\${gid}\`, String(Date.now()));
      } catch (e) {
        console.warn(\`[DOOR POLL] \${gid} failed: \${e.message}\`);
      }
    }
  };

  // ── gapFillDoorEntries — run on startup to recover missing historical days ──
  // Checks each of the last 30 days. If a day has 0 count in SQLite,
  // fetches it from Firestore and saves to disk. After this, the SQLite
  // disk is the complete source of truth for historical data.
  router.gapFillDoorEntries = async function gapFillDoorEntries() {
    console.log('[GAP FILL] Checking last 30 days for missing door entry data...');
    const gaps = [];

    for (let i = 1; i <= 30; i++) {
      const d = new Date(Date.now() + 3600000 - i * 86400000);
      const dateStr = d.toISOString().slice(0, 10);
      for (const [gid] of Object.entries(GYM_DOOR_MAP)) {
        const stat = lc.getDailyStat(gid, dateStr);
        if (!stat || stat.count === 0) gaps.push({ gid, dateStr });
      }
    }

    if (gaps.length === 0) {
      console.log('[GAP FILL] No gaps found — disk is complete ✅');
      return;
    }

    console.log(\`[GAP FILL] Found \${gaps.length} missing days — fetching from Firestore...\`);

    for (const { gid, dateStr } of gaps) {
      const g = GYM_DOOR_MAP[gid];
      if (!g) continue;
      const nextDay = new Date(new Date(dateStr).getTime() + 86400000).toISOString().slice(0, 10);
      let bestUnique = 0, bestTotal = 0;

      for (const coll of g.collections) {
        try {
          // Fetch last doc (has device's daily totals embedded)
          const body = {
            structuredQuery: {
              from: [{ collectionId: coll }],
              where: {
                compositeFilter: {
                  op: 'AND',
                  filters: [
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: dateStr } } },
                    { fieldFilter: { field: { fieldPath: 'timestamp' }, op: 'LESS_THAN', value: { stringValue: nextDay } } }
                  ]
                }
              },
              orderBy: [{ field: { fieldPath: 'timestamp' }, direction: 'DESCENDING' }],
              limit: 1,
            }
          };

          const resp = await fetch(DOOR_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          if (!resp.ok) continue;
          const data = await resp.json();
          if (!Array.isArray(data) || !data[0]?.document) continue;

          const doc = data[0].document;
          const f   = doc.fields || {};
          const loc = (f.location?.stringValue || '').toLowerCase();
          const tags = g.locationTags.map(t => t.toLowerCase());
          if (!tags.some(t => loc.includes(t) || t.includes(loc))) continue;

          const du = f.daily_unique?.integerValue != null ? parseInt(f.daily_unique.integerValue) :
                     f.daily_unique?.doubleValue  != null ? Math.round(f.daily_unique.doubleValue) : 0;
          const dt = f.daily_total?.integerValue  != null ? parseInt(f.daily_total.integerValue) :
                     f.daily_total?.doubleValue   != null ? Math.round(f.daily_total.doubleValue) : 0;
          if (du > bestUnique) { bestUnique = du; bestTotal = dt; }
        } catch (e) {
          console.warn(\`[GAP FILL] \${gid}/\${dateStr}/\${coll}: \${e.message}\`);
        }
      }

      if (bestUnique > 0) {
        lc.upsertDailyStat(gid, dateStr, bestUnique, bestTotal);
        console.log(\`[GAP FILL] ✅ \${gid} / \${dateStr}: \${bestUnique} unique saved to disk\`);
      } else {
        console.log(\`[GAP FILL] ⚠️  \${gid} / \${dateStr}: no data available in Firestore\`);
      }
    }
    console.log('[GAP FILL] Complete — SQLite disk is now the source of truth 💾');
  };

`;

code = code.replace(POLL_OLD, POLL_NEW);
fs.writeFileSync(analyticsFile, code, 'utf8');
console.log('✅ analytics.js patched — pollDoorEntries now saves 20 entries/poll + gapFillDoorEntries added');
console.log('   Old poll length:', POLL_OLD.length, 'chars');
