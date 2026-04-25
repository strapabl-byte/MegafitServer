// auto_sync.js — Optimized: reads daily_unique/daily_total from latest doc (1 read per gym)
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY || "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

let lc; // lazy-load to avoid circular dependency issues
function getLC() {
  if (!lc) lc = require('./localCache');
  return lc;
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

  const body = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: {
        fieldFilter: {
          field: { fieldPath: "timestamp" },
          op: "GREATER_THAN_OR_EQUAL",
          value: { stringValue: dateStr }
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
  let unique = 0;
  for (const doc of sorted) {
    const f   = doc.fields;
    const uid = f.user_id?.stringValue || f.id?.stringValue || doc.name.split("/").pop();
    const t   = new Date(f.timestamp?.stringValue || 0).getTime();
    if (!seen.has(uid) || Math.abs(t - seen.get(uid)) >= 600000) {
      unique++;
      seen.set(uid, t);
    }
  }
  return { unique, raw: filtered.length };
}

const parseNum = (field) => {
  if (!field) return null;
  if (field.integerValue !== undefined) return parseInt(field.integerValue);
  if (field.doubleValue  !== undefined) return Math.round(field.doubleValue);
  return null;
};

async function syncGymCounts(db, apiCache, daysBack = 1, checkQuota = () => false) {
  if (checkQuota()) {
    console.warn("⚠️ [SYNC SKIPPED] Quota exceeded. Silence mode active.");
    return;
  }
  const admin = require("firebase-admin");
  const today = moroccoDateStr();

  // Build list of dates to sync (today + past N days)
  const dates = [];
  for (let i = 0; i <= daysBack; i++) {
    dates.push(moroccoDateStr(new Date(Date.now() - i * 86400000)));
  }

  console.log(`🔄 Auto-sync starting for: ${dates.join(", ")}`);

  for (const gym of GYM_SYNC_MAP) {
    for (const dateStr of dates) {
      try {
        let unique = 0, raw = 0;
        const allCollections = gym.collections || [gym.collection];
        const tags = (gym.locationTags || [gym.locationTag || '']).map(t => t.toLowerCase().trim());

        if (dateStr === today) {
          // ── TODAY: incremental — only fetch docs newer than what's in SQLite ──
          // The live pollDoorEntries (every 60s) already handles this continuously.
          // Here we just make sure daily_stats is up to date from SQLite counts.
          const sqliteUnique = getLC().getUniqueEntryCount(gym.id, dateStr);
          const sqliteRaw    = getLC().getEntryCount(gym.id, dateStr);

          // Also try to get the latest device-reported total (1 read per collection)
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

          // Use whichever is higher — device counter or SQLite count
          unique = Math.max(sqliteUnique, deviceUnique);
          raw    = Math.max(sqliteRaw, deviceRaw);
          console.log(`  📡 ${gym.id} / ${dateStr}: ${unique} unique (device:${deviceUnique} sqlite:${sqliteUnique})`);

        } else {
          // ── PAST DAYS: 1 read per collection — last doc carries the day's total ──
          // The door device embeds daily_unique/daily_total in every scan.
          // The last scan of the day has the final count. Zero Firestore waste.
          for (const coll of allCollections) {
            const latestDoc = await fetchLatestDoc(coll, dateStr);
            if (!latestDoc) continue;
            const f = latestDoc.fields || {};
            // Verify this doc belongs to this gym location
            const loc = (f.location?.stringValue || '').toLowerCase();
            if (!tags.some(t => loc === t || loc.includes(t) || t.includes(loc))) continue;
            const du = parseNum(f.daily_unique);
            const dt = parseNum(f.daily_total);
            if (du !== null) {
              unique = Math.max(unique, du);
              raw    = Math.max(raw, dt || du);
            }
          }

          // Fallback: if device fields are missing, use what we already have in SQLite
          if (unique === 0) {
            unique = getLC().getUniqueEntryCount(gym.id, dateStr);
            raw    = getLC().getEntryCount(gym.id, dateStr);
            if (unique > 0) console.log(`  📦 ${gym.id} / ${dateStr}: ${unique} unique (SQLite fallback — no device counter)`);
            else            console.log(`  ⚠️  ${gym.id} / ${dateStr}: no data found`);
          } else {
            console.log(`  ✅ ${gym.id} / ${dateStr}: ${unique} unique, ${raw} raw (1-read from device counter)`);
          }
        }

        // Save to SQLite daily_stats (the chart reads from here — zero Firestore cost)
        getLC().upsertDailyStat(gym.id, dateStr, unique, raw);

        // Write summary to Firestore gym_daily_stats (fire-and-forget backup)
        db.collection("gym_daily_stats").doc(`${gym.id}_${dateStr}`).set(
          { gym_id: gym.id, date: dateStr, count: unique, rawCount: raw, lastSyncedAt: admin.firestore.FieldValue.serverTimestamp() },
          { merge: true }
        ).catch(e => console.warn(`  ⚠️ Firestore write failed for ${gym.id}/${dateStr}:`, e.message));

        // Invalidate RAM cache
        if (apiCache?.dailyStats) delete apiCache.dailyStats[gym.id];
      } catch (err) {
        console.error(`  ❌ Sync failed for ${gym.id} / ${dateStr}:`, err.message);
      }
    }
    
    // 💸 SYNC DAILY REGISTER (Payments)
    try {
      for (const dateStr of dates) {
        const gymId = gym.id;
        const docId = `${gymId}_${dateStr}`;
        const snap = await db.collection("megafit_daily_register")
          .doc(docId)
          .collection("entries")
          .orderBy("createdAt", "asc")
          .get();
        
        if (!snap.empty) {
          const entries = snap.docs.map(d => {
            const data = d.data();
            // Convert Firestore timestamps to ISO strings for SQLite
            const createdAtStr = data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : 
                                 (data.createdAt || new Date().toISOString());
            return { 
              id: d.id, 
              ...data, 
              createdAt: createdAtStr 
            };
          });
          getLC().upsertRegister(gymId, dateStr, entries);
          console.log(`  💸 Synced ${entries.length} register entries for ${gymId} / ${dateStr}`);
        }
      }
    } catch (err) {
      console.error(`  ❌ Register sync failed for ${gym.id}:`, err.message);
    }
  }
  console.log("✨ Auto-sync complete.");
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
    syncGymCounts(db, apiCache, 7, checkQuota).catch(e => console.error("❌ Nightly sync error:", e));
    scheduleNightlySync(db, apiCache, checkQuota); // reschedule for next night
  }, msToNight);

  // ── Hourly today-only sync ───────────────────────────────────────────────
  // Runs every 60 minutes — uses 1 read per gym (fast path)
  setInterval(() => {
    const h = new Date(Date.now() + 3600000).getHours(); // Morocco hour
    if (h >= 7 && h <= 23) { // Only during gym hours
      console.log(`⏱️  Hourly sync triggered (${h}:xx Morocco)`);
      syncGymCounts(db, apiCache, 0, checkQuota).catch(e => console.error("❌ Hourly sync error:", e));
    }
  }, 60 * 60 * 1000); // every 60 minutes

  console.log(`⏱️  Hourly sync active (every 60min, 07:00–23:00 Morocco)`);
}

module.exports = { syncGymCounts, scheduleNightlySync };
