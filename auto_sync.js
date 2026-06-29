// auto_sync.js — Optimized: reads daily_unique/daily_total from latest doc (1 read per gym)
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY || "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

let lc; // lazy-load to avoid circular dependency issues
function getLC() {
  if (!lc) lc = require('./localCache');
  return lc;
}

// ── CANONICAL GYM IDs ─────────────────────────────────────────────────────────
const CANONICAL_GYMS = ['dokarat', 'marjane', 'casa1', 'casa2'];

/**
 * 🏦 STRICT GYM RESOLVER — used everywhere member/inscription data is classified.
 * Priority: canonical gymId field → location string map → null (NO silent fallback).
 * Returns null if unknown, never silently assigns to a wrong gym.
 */
function resolveGymId(m) {
  // Priority 1: direct canonical gymId on the document
  const direct = (m.gymId || '').toLowerCase().trim();
  if (CANONICAL_GYMS.includes(direct)) return direct;

  // Priority 2: canonical location string map (all known variants)
  const loc = (m.location || m.gymId || '').toLowerCase().trim();
  if (['dokkarat fes', 'dokkarat', 'doukkarate', 'fes dokkarat', 'dokarat', 'dukkarate'].some(s => loc.includes(s))) return 'dokarat';
  if (['fes saiss', 'marjane', 'fes marjane', 'saiss', 'fès saiss', 'fes-saiss'].some(s => loc.includes(s))) return 'marjane';
  if (['casa 1', 'casa1', 'anfa', 'casa anfa', 'casaanfa'].some(s => loc.includes(s)) && !loc.includes('lady')) return 'casa1';
  if (['casa 2', 'casa2', 'casa lady', 'lady anfa', 'casalady'].some(s => loc.includes(s))) return 'casa2';

  // ⚠️ Unknown — log and return null. NEVER silently fall back to a default gym.
  if (loc) console.warn(`[SYNC] ⚠️ Unknown gym location for member ${m.id}: gymId="${m.gymId}", location="${m.location}". Skipped — no silent fallback.`);
  return null;
}

const GYM_SYNC_MAP = [
  { 
    id: "dokarat", 
    collection: "mega_fit_logs",      
    locationTags: ["dokkarat fes"],
    collections: ["mega_fit_logs"] 
  },
  { 
    id: "marjane", 
    collection: "saiss entrees logs", 
    locationTags: ["fes saiss", "fes marjane"], // flexible matching
    collections: ["saiss entrees logs", "mega_fit_logs"], // aggregate leaked logs
  },
  { id: "casa1", collection: null, collections: [] },
  { id: "casa2", collection: null, collections: [] },
];

function moroccoDateStr(date = new Date()) {
  return new Date(date.getTime() + 3600000).toISOString().slice(0, 10);
}

/**
 * NEW: Fetch only the LATEST 1 document for a given date.
 * The device embeds daily_total and daily_unique in every entry.
 * 1 read = perfect accuracy. Falls back to old method if fields missing.
 */
async function fetchLatestDoc(collectionName, dateStr) {
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;
  const nextDay = new Date(new Date(dateStr).getTime() + 86400000).toISOString().slice(0, 10);

  const body = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: {
        compositeFilter: {
          op: "AND",
          filters: [
            {
              fieldFilter: {
                field: { fieldPath: "timestamp" },
                op: "GREATER_THAN_OR_EQUAL",
                value: { stringValue: dateStr }
              }
            },
            {
              fieldFilter: {
                field: { fieldPath: "timestamp" },
                op: "LESS_THAN",
                value: { stringValue: nextDay }
              }
            }
          ]
        }
      },
      orderBy: [{ field: { fieldPath: "timestamp" }, direction: "DESCENDING" }],
      limit: 1
    }
  };

  try {
    const res  = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!Array.isArray(data) || !data[0]?.document) return null;
    return data[0].document;
  } catch (err) {
    console.error(`  ❌ REST Fetch failed for ${collectionName}:`, err.message);
    return null;
  }
}

/**
 * Fetch docs for ONE specific date using a range query (>= dateStr AND < nextDay).
 * This ensures we get the right docs regardless of how far back the date is.
 */
async function fetchRecentLogsFromCollections(collectionNames, dateStr, limit = 2000) {
  const allDocs = [];

  // Build the next day string for the upper bound
  const nextDay = new Date(new Date(dateStr).getTime() + 86400000).toISOString().slice(0, 10);

  for (const coll of collectionNames) {
    const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;
    const body = {
      structuredQuery: {
        from: [{ collectionId: coll }],
        where: {
          compositeFilter: {
            op: "AND",
            filters: [
              {
                fieldFilter: {
                  field: { fieldPath: "timestamp" },
                  op: "GREATER_THAN_OR_EQUAL",
                  value: { stringValue: dateStr }
                }
              },
              {
                fieldFilter: {
                  field: { fieldPath: "timestamp" },
                  op: "LESS_THAN",
                  value: { stringValue: nextDay }
                }
              }
            ]
          }
        },
        orderBy: [{ field: { fieldPath: "timestamp" }, direction: "ASCENDING" }],
        limit: limit
      }
    };

    try {
      const res  = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      if (Array.isArray(data)) {
        const docs = data.filter(item => item.document).map(item => item.document);
        allDocs.push(...docs);
      }
    } catch (err) {
      console.error(`  ❌ REST Fetch fallback failed for ${coll}:`, err.message);
    }
  }
  return allDocs;
}

function deduplicateForDate(docs, targetTags, dateStr) {
  const tags = targetTags.map(t => t.toLowerCase().trim());
  
  const filtered = docs.filter(doc => {
    const fields = doc.fields || {};
    const timestamp = fields.timestamp?.stringValue || "";
    if (!timestamp.startsWith(dateStr)) return false;
    
    const loc = (fields.location?.stringValue || "").toLowerCase().trim();
    // Match any of the target tags precisely or via inclusion
    return tags.some(t => loc === t || loc.includes(t) || t.includes(loc));
  });

  const sorted = [...filtered].sort((a, b) =>
    (a.fields.timestamp?.stringValue || "").localeCompare(b.fields.timestamp?.stringValue || "")
  );

  const seen = new Map();
  const rawEntries = [];
  let unique = 0;
  for (const doc of sorted) {
    const f   = doc.fields;
    const uid = f.user_id?.stringValue || f.id?.stringValue || doc.name.split("/").pop();
    const t   = new Date(f.timestamp?.stringValue || 0).getTime();
    
    // Always store the raw entry for historical tracking
    rawEntries.push({
      id: doc.name.split("/").pop(),
      timestamp: f.timestamp?.stringValue || '',
      name: f.name?.stringValue || '',
      method: f.method?.stringValue || '',
      status: f.status?.stringValue || '',
      user_id: f.user_id?.stringValue || null,
      isFace: (f.method?.stringValue || '').toLowerCase().includes('visage')
    });

    if (!seen.has(uid) || Math.abs(t - seen.get(uid)) >= 600000) {
      unique++;
      seen.set(uid, t);
    }
  }
  return { unique, raw: filtered.length, rawEntries };
}

const parseNum = (field) => {
  if (!field) return null;
  if (field.integerValue !== undefined) return parseInt(field.integerValue);
  if (field.doubleValue  !== undefined) return Math.round(field.doubleValue);
  return null;
};

async function syncGymCounts(db, apiCache, daysBack = 1, checkQuota = () => false, forceManual = false, options = {}) {
  if (checkQuota()) {
    console.warn("⚠️ [SYNC SKIPPED] Quota exceeded. Silence mode active.");
    return;
  }
  const admin = require("firebase-admin");
  const today = moroccoDateStr();
  const syncRegisterOnly = options.syncRegisterOnly || false;

  // Build list of dates to sync (today + past N days)
  const dates = [];
  for (let i = 0; i <= daysBack; i++) {
    dates.push(moroccoDateStr(new Date(Date.now() - i * 86400000)));
  }

  console.log(`🔄 Sync starting for: ${dates.join(", ")} (Register Only: ${syncRegisterOnly}, Force Manual: ${forceManual})`);

  // 1️⃣ Sync Doors (Skip if syncRegisterOnly is true)
  if (!syncRegisterOnly) {
    for (const gym of GYM_SYNC_MAP) {
      if (!gym.collection && (!gym.collections || gym.collections.length === 0)) continue;
      for (const dateStr of dates) {
        try {
          let unique = 0, raw = 0;
          const allCollections = gym.collections || [gym.collection];
          const tags = (gym.locationTags || [gym.locationTag || '']).map(t => t.toLowerCase().trim());

          if (dateStr === today && !forceManual) {
            const sqliteUnique = getLC().getUniqueEntryCount(gym.id, dateStr);
            const sqliteRaw    = getLC().getEntryCount(gym.id, dateStr);

            let deviceUnique = 0, deviceRaw = 0;
            for (const coll of allCollections) {
              const latestDoc = await fetchLatestDoc(coll, dateStr);
              if (!latestDoc) continue;
              const f = latestDoc.fields || {};
              const loc = (f.location?.stringValue || '').toLowerCase();
              if (!tags.some(t => loc === t || loc.includes(t) || t.includes(loc))) continue;
              const du = parseNum(f.daily_unique);
              const dt = parseNum(f.daily_total);
              if (du !== null) { deviceUnique = Math.max(deviceUnique, du); deviceRaw = Math.max(deviceRaw, dt || du); }
            }

            unique = Math.max(sqliteUnique, deviceUnique);
            raw    = Math.max(sqliteRaw, deviceRaw);
            console.log(`  📡 ${gym.id} / ${dateStr}: ${unique} unique (device:${deviceUnique} sqlite:${sqliteUnique})`);

          } else {
            for (const coll of allCollections) {
              const latestDoc = await fetchLatestDoc(coll, dateStr);
              if (!latestDoc) continue;
              const f = latestDoc.fields || {};
              const loc = (f.location?.stringValue || '').toLowerCase();
              if (!tags.some(t => loc === t || loc.includes(t) || t.includes(loc))) continue;
              const du = parseNum(f.daily_unique);
              const dt = parseNum(f.daily_total);
              if (du !== null) {
                unique = Math.max(unique, du);
                raw    = Math.max(raw, dt || du);
              }
            }

            if (unique === 0 || forceManual) {
              const docs = await fetchRecentLogsFromCollections(allCollections, dateStr);
              const res  = deduplicateForDate(docs, tags, dateStr);
              unique = res.unique;
              raw    = res.raw;
              if (res.rawEntries && res.rawEntries.length > 0) {
                 getLC().upsertEntries(gym.id, res.rawEntries);
              }
              if (unique > 0) console.log(`  🔍 ${gym.id} / ${dateStr}: ${unique} unique (${forceManual ? 'Deep Scan repair/historical' : 'Manual count fallback'})`);
              else            console.log(`  ⚠️  ${gym.id} / ${dateStr}: no data found even in logs`);
            } else {
              console.log(`  ✅ ${gym.id} / ${dateStr}: ${unique} unique, ${raw} raw (1-read from device counter)`);
            }
          }

          getLC().upsertDailyStat(gym.id, dateStr, unique, raw);

          db.collection("gym_daily_stats").doc(`${gym.id}_${dateStr}`).set(
            { gym_id: gym.id, date: dateStr, count: unique, rawCount: raw, lastSyncedAt: admin.firestore.FieldValue.serverTimestamp() },
            { merge: true }
          ).catch(e => console.warn(`  ⚠️ Firestore write failed for ${gym.id}/${dateStr}:`, e.message));

          if (apiCache?.dailyStats) delete apiCache.dailyStats[gym.id];
        } catch (err) {
          console.error(`  ❌ Door sync failed for ${gym.id} / ${dateStr}:`, err.message);
        }
      }
    }
  }

  // 2️⃣ Sync Daily Register (Payments) — for all gyms in GYM_SYNC_MAP
  for (const gym of GYM_SYNC_MAP) {
    try {
      for (const dateStr of dates) {
        const gymId = gym.id;
        console.log(`  🔍 [REGISTER] Checking ${gymId} for ${dateStr}...`);
        const docId = `${gymId}_${dateStr}`;
        const snap = await db.collection("megafit_daily_register")
          .doc(docId)
          .collection("entries")
          .orderBy("createdAt", "asc")
          .get();
        
        if (!snap.empty) {
          const entries = snap.docs.map(d => {
            const data = d.data();
            const createdAtStr = data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : 
                                 (data.createdAt || new Date().toISOString());
            return { id: d.id, ...data, createdAt: createdAtStr };
          });
          getLC().upsertRegister(gymId, dateStr, entries);
          console.log(`  💸 Synced ${entries.length} register entries for ${gymId} / ${dateStr}`);
        }

        const decSnap = await db.collection("megafit_daily_register")
          .doc(docId)
          .collection("decaissements")
          .orderBy("createdAt", "asc")
          .get();
        if (!decSnap.empty) {
          getLC().upsertDecaissements(gymId, dateStr, decSnap.docs.map(d => ({ id: d.id, ...d.data() })));
        }
      }
    } catch (err) {
      console.error(`  ❌ Register sync failed for ${gym.id}:`, err.message);
    }
  }

  // 3️⃣ Optimized Member/Pending Sync (Runs ALWAYS on hourly/nightly/manual syncs to keep SQLite updated)
  console.log("  👥 Optimized Member/Pending Sync...");
  try {
    // Pull latest members (last 48 hours)
    const twoDaysAgo = new Date(Date.now() - 48 * 60 * 60 * 1000);
    const membersSnap = await db.collection('members').where('updatedAt', '>=', twoDaysAgo).get();
    if (!membersSnap.empty) {
      const gyms = {};
      let skipped = 0;
      membersSnap.docs.forEach(d => {
        const m = { id: d.id, ...d.data() };
        // 🏦 STRICT: Use canonical resolver — no silent fallback to dokarat
        const gid = resolveGymId(m);
        if (!gid) { skipped++; return; } // unknown gym — skip, do NOT contaminate
        if (!gyms[gid]) gyms[gid] = [];
        gyms[gid].push(m);
      });
      for (const [gid, list] of Object.entries(gyms)) {
        getLC().upsertMembers(gid, list);
      }
      console.log(`  ✅ Synced ${membersSnap.size - skipped} recently updated members (${skipped} skipped — unknown gym).`);
    }

    // 1. Fetch ALL currently active pending inscriptions from Firestore (status: pending, awaiting_payment, locked)
    // This is a very small query (normally <10 docs total) and guarantees we stay up to date.
    const activePendingSnap = await db.collection('pending_members')
      .where('status', 'in', ['pending', 'awaiting_payment', 'locked'])
      .get();

    const activeIds = new Set();
    if (!activePendingSnap.empty) {
      let pendingSkipped = 0;
      activePendingSnap.docs.forEach(d => {
        const data = { id: d.id, ...d.data() };
        activeIds.add(d.id);
        // Guard: skip pending inscriptions with invalid gymId
        if (!CANONICAL_GYMS.includes(data.gymId)) {
          console.warn(`[SYNC] ⚠️ Pending inscription ${d.id} has invalid gymId "${data.gymId}" — skipped.`);
          pendingSkipped++;
          return;
        }
        getLC().setPending(data);
      });
      console.log(`  ✅ Synced ${activePendingSnap.size - pendingSkipped} active pending inscriptions (${pendingSkipped} skipped).`);
    }

    // 2. Also pull recently updated pending inscriptions (last 48h) to catch recently converted ones
    const twoDaysAgoPending = new Date(Date.now() - 48 * 60 * 60 * 1000);
    const updatedPendingSnap = await db.collection('pending_members')
      .where('updatedAt', '>=', twoDaysAgoPending)
      .get();

    if (!updatedPendingSnap.empty) {
      updatedPendingSnap.docs.forEach(d => {
        const data = { id: d.id, ...d.data() };
        if (CANONICAL_GYMS.includes(data.gymId)) {
          getLC().setPending(data);
        }
      });
      console.log(`  ✅ Synced ${updatedPendingSnap.size} recently updated pending/converted inscriptions.`);
    }

    // 3. Mark any local pending cache records that are NOT in the active list (and were not recently updated to another active status) as 'converted' (or sync their firestore status)
    const localActive = getLC().db.prepare(`
      SELECT id FROM pending_cache WHERE status IN ('pending', 'awaiting_payment', 'locked')
    `).all();

    for (const row of localActive) {
      if (!activeIds.has(row.id)) {
        // It's no longer active in Firestore. Let's verify its actual status from Firestore, or just update it to converted
        try {
          const doc = await db.collection('pending_members').doc(row.id).get();
          if (doc.exists) {
            const status = doc.data().status || 'converted';
            getLC().updatePendingStatus(row.id, status);
          } else {
            // Deleted in Firestore
            getLC().db.prepare('DELETE FROM pending_cache WHERE id = ?').run(row.id);
            console.log(`  🧹 Deleted stale inscription ${row.id} from local cache.`);
          }
        } catch (err) {
          // Fallback: set to converted
          getLC().updatePendingStatus(row.id, 'converted');
        }
      }
    }
  } catch (err) {
    console.warn("  ⚠️ Optimized Member/Pending Sync failed:", err.message);
  }

  console.log("✨ Sync complete.");
}

/**
 * Sync manager activity logs from Firestore → SQLite
 * Incremental: only fetches docs since last sync timestamp
 * Nightly: full 30-day backfill
 */
async function syncActivityLogs(db, daysBack = 1) {
  try {
    const lc = getLC();
    const lastSync = lc.getMeta('activity_logs_last_sync');
    const sinceDate = daysBack > 7
      ? new Date(Date.now() - daysBack * 86400000)  // nightly: full backfill
      : lastSync
        ? new Date(lastSync)
        : new Date(Date.now() - 24 * 60 * 60 * 1000); // default: last 24h

    console.log(`  📋 [ACTIVITY] Syncing logs since ${sinceDate.toISOString().slice(0, 16)}...`);

    const snap = await db.collection('manager_activity_logs')
      .where('createdAt', '>=', sinceDate)
      .orderBy('createdAt', 'desc')
      .limit(2000)
      .get();

    if (snap.empty) {
      console.log('  📋 [ACTIVITY] No new logs found.');
      lc.setMeta('activity_logs_last_sync', new Date().toISOString());
      return;
    }

    const GYM_NAMES_MAP = { dokarat: 'Doukkarate', marjane: 'Saïss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
    const GYM_COLORS_MAP = { dokarat: '#a3ff12', marjane: '#3b82f6', casa1: '#f59e0b', casa2: '#ec4899' };

    const logs = snap.docs.map(doc => {
      const d = doc.data();
      const email = (d.userEmail || '').toLowerCase();
      const createdAt = d.createdAt?.toDate ? d.createdAt.toDate().toISOString() : new Date().toISOString();

      // Derive page
      let page = d.page || 'Système';
      if (!d.page) {
        const path = d.path || '';
        if (path.includes('/register'))       page = 'Registre';
        else if (path.includes('/payments'))  page = 'Paiements';
        else if (path.includes('/inscriptions')) page = 'Inscriptions';
        else if (path.includes('/members'))   page = 'Membres';
        else if (path.includes('/courses'))   page = 'Cours';
        else if (path.includes('/coaches'))   page = 'Coachs';
        else if (path.includes('/sales'))     page = 'Commerciaux';
        else if (path.includes('/relance'))   page = 'Relance';
        else if (path.includes('/scan'))      page = 'Scanner';
        else if (path.includes('/push'))      page = 'Notifications';
        else if (path.includes('/auralix'))   page = 'Auralix';
        else if (path.includes('/email'))     page = 'Email';
        else if (path.includes('/config'))    page = 'Configuration';
      }

      // Derive role
      let userRole = d.userRole || 'unknown';
      if (d.source === 'inscription_pwa') {
        userRole = 'commercial_pwa';
      } else if (email.includes('megafitrh'))          userRole = 'rh';
      else if (email.includes('performance'))           userRole = 'performance_manager';
      else if (email.includes('megafitsaiss') || email.includes('megafitdokkarat') ||
               email.includes('megafitanfa') || email.includes('megafitlady'))
                                                        userRole = 'manager';
      else if (d.userId !== 'system_id' && d.userId !== 'pwa_inscription') userRole = 'admin';

      // Club info
      const club = d.club || { id: d.gymId || 'system', name: GYM_NAMES_MAP[d.gymId] || 'System', color: GYM_COLORS_MAP[d.gymId] || '#999' };

      return {
        id: doc.id,
        gymId: d.gymId || 'system',
        userEmail: d.userEmail || email || '',
        userName: d.userName || 'System',
        userRole,
        action: d.action || 'Unknown',
        page,
        method: d.method || '',
        club,
        source: d.source || '',
        createdAt,
      };
    });

    lc.upsertActivityLogs(logs);
    lc.setMeta('activity_logs_last_sync', new Date().toISOString());
    console.log(`  ✅ [ACTIVITY] Cached ${logs.length} activity logs to SQLite.`);
  } catch (err) {
    console.error('  ❌ [ACTIVITY] Sync failed:', err.message);
  }
}

/**
 * Schedule: hourly during the day (08:00–23:00 Morocco) + nightly at 00:05
 */
function scheduleNightlySync(db, apiCache, checkQuota = () => false) {
  // ── Nightly full sync at 00:05 Morocco ──────────────────────────────────
  const moroccoNow = new Date(Date.now() + 3600000);
  const nextNight  = new Date(moroccoNow);
  nextNight.setHours(0, 5, 0, 0);
  if (nextNight <= moroccoNow) nextNight.setDate(nextNight.getDate() + 1);
  const msToNight = nextNight.getTime() - moroccoNow.getTime();

  console.log(`⏰ Nightly sync scheduled in ${Math.round(msToNight / 60000)} min (00:05 Morocco)`);
  setTimeout(() => {
    // Nightly sync uses forceManual=true to ensure we pull the FULL LIST of raw entries into SQLite
    syncGymCounts(db, apiCache, 7, checkQuota, true).catch(e => console.error("❌ Nightly sync error:", e));
    // Nightly: full 30-day activity logs backfill
    syncActivityLogs(db, 30).catch(e => console.error("❌ Nightly activity sync error:", e));
    scheduleNightlySync(db, apiCache, checkQuota); // reschedule for next night
  }, msToNight);

  // ── Hourly today-only sync ───────────────────────────────────────────────
  // Runs every 60 minutes — uses 1 read per gym (fast path)
  setInterval(() => {
    const h = new Date(Date.now() + 3600000).getHours(); // Morocco hour
    if (h >= 7 && h <= 23) { // Only during gym hours
      console.log(`⏱️  Hourly sync triggered (${h}:xx Morocco)`);
      syncGymCounts(db, apiCache, 0, checkQuota).catch(e => console.error("❌ Hourly sync error:", e));
      // Hourly: incremental activity logs sync (last 1 day)
      syncActivityLogs(db, 1).catch(e => console.error("❌ Hourly activity sync error:", e));
    }
  }, 60 * 60 * 1000); // every 60 minutes

  console.log(`⏱️  Hourly sync active (every 60min, 07:00–23:00 Morocco)`);

  // ── Startup: catch-up activity logs sync ─────────────────────────────────
  syncActivityLogs(db, 7).catch(e => console.error("❌ Startup activity sync error:", e));
}

module.exports = { syncGymCounts, scheduleNightlySync, syncActivityLogs };

