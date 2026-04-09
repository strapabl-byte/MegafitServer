// auto_sync.js — Improved nightly sync with sorting and robust filtering
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY || "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

const GYM_SYNC_MAP = [
  { id: "dokarat", collection: "mega_fit_logs",      locationTag: "dokkarat fes" },
  { id: "marjane", collection: "saiss entrees logs", locationTag: "fes saiss"    },
];

function moroccoDateStr(date = new Date()) {
  return new Date(date.getTime() + 3600000).toISOString().slice(0, 10);
}

/**
 * ✅ IMPROVED: Fetches documents for a specific date range with ORDERING.
 * Using order ensures we get the most recent data even if we hit the limit.
 */
async function fetchRecentLogs(collectionName, dateStr, limit = 2000) {
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
      orderBy: [
        { field: { fieldPath: "timestamp" }, direction: "DESCENDING" }
      ],
      limit: limit
    }
  };

  try {
    const res  = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json();

    if (!Array.isArray(data)) {
      console.warn(`  ⚠️  runQuery returned non-array for ${collectionName}:`, JSON.stringify(data).slice(0, 200));
      return [];
    }

    return data.filter(item => item.document).map(item => item.document);
  } catch (err) {
    console.error(`  ❌ REST Fetch failed for ${collectionName}:`, err.message);
    return [];
  }
}

function deduplicateForDate(docs, locationTag, dateStr) {
  const targetLoc = locationTag.toLowerCase().trim();
  
  // Filter by date string and location
  const filtered = docs.filter(doc => {
    const fields = doc.fields || {};
    const timestamp = fields.timestamp?.stringValue || "";
    if (!timestamp.startsWith(dateStr)) return false;

    const loc = (fields.location?.stringValue || "").toLowerCase().trim();
    // Inclusive matching for location names
    return loc === targetLoc || loc.includes(targetLoc) || targetLoc.includes(loc) || (targetLoc === "fes saiss" && loc === "");
  });

  // Sort chronologically for unique counting
  const sorted = [...filtered].sort((a, b) =>
    (a.fields.timestamp?.stringValue || "").localeCompare(b.fields.timestamp?.stringValue || "")
  );

  const seen = new Map();
  let unique = 0;
  for (const doc of sorted) {
    const f   = doc.fields;
    const uid = f.user_id?.stringValue || f.id?.stringValue || doc.name.split("/").pop();
    const t   = new Date(f.timestamp?.stringValue || 0).getTime();
    
    // 10-minute timeout for unique re-entry
    if (!seen.has(uid) || Math.abs(t - seen.get(uid)) >= 600000) {
      unique++;
      seen.set(uid, t);
    }
  }
  return { unique, raw: filtered.length };
}

async function syncGymCounts(db, apiCache, daysBack = 1) {
  const dates = [];
  for (let i = 0; i <= daysBack; i++) {
    dates.push(moroccoDateStr(new Date(Date.now() - i * 86400000)));
  }
  
  console.log(`🔄 Auto-sync starting for: ${dates.join(", ")}`);
  const admin = require("firebase-admin");

  for (const gym of GYM_SYNC_MAP) {
    // Fetch a large chunk of recent logs once per gym to save quota
    const oldestDate = dates[dates.length - 1];
    const allRecentDocs = await fetchRecentLogs(gym.collection, oldestDate);
    
    for (const dateStr of dates) {
      try {
        const { unique, raw } = deduplicateForDate(allRecentDocs, gym.locationTag, dateStr);

        await db.collection("gym_daily_stats").doc(`${gym.id}_${dateStr}`).set(
          { 
            gym_id: gym.id, 
            date: dateStr, 
            count: unique, 
            rawCount: raw,
            lastSyncedAt: admin.firestore.FieldValue.serverTimestamp() 
          },
          { merge: true }
        );
        console.log(`  ✅ ${gym.id} / ${dateStr}: ${unique} unique (${raw} raw)`);

        if (apiCache?.dailyStats?.delete) apiCache.dailyStats.delete(gym.id);
      } catch (err) {
        console.error(`  ❌ Sync failed for ${gym.id} / ${dateStr}:`, err.message);
      }
    }
  }
  console.log("✨ Auto-sync complete.");
}

function scheduleNightlySync(db, apiCache) {
  const moroccoNow = new Date(Date.now() + 3600000);
  const nextRun    = new Date(moroccoNow);
  nextRun.setHours(0, 5, 0, 0); // 00:05 Morocco time
  if (nextRun <= moroccoNow) nextRun.setDate(nextRun.getDate() + 1);
  
  const ms = nextRun.getTime() - moroccoNow.getTime();
  console.log(`⏰ Nightly sync scheduled in ${Math.round(ms / 60000)} min (00:05 Morocco)`);
  
  setTimeout(() => {
    syncGymCounts(db, apiCache, 7).catch(e => console.error("❌ Nightly sync error:", e));
    scheduleNightlySync(db, apiCache);
  }, ms);
}

module.exports = { syncGymCounts, scheduleNightlySync };
