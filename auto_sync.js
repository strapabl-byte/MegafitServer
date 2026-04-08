// auto_sync.js — Efficient nightly sync using date-filtered queries
// Uses runQuery (cheap) instead of fetching the entire collection

const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY || "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

const GYM_SYNC_MAP = [
  { id: "dokarat", collection: "mega_fit_logs",      locationTag: "dokkarat fes" },
  { id: "marjane", collection: "saiss entrees logs", locationTag: "fes saiss"    },
];

// Returns YYYY-MM-DD in Morocco time (UTC+1)
function moroccoDateStr(date = new Date()) {
  return new Date(date.getTime() + 3600000).toISOString().slice(0, 10);
}

// ✅ EFFICIENT: Fetches only documents for a specific date using runQuery
// Cost: ~N reads where N = entries that day, NOT a full collection scan
async function fetchByDate(collectionName, dateStr) {
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
      limit: 1000
    }
  };

  const res  = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();

  if (!Array.isArray(data)) {
    console.warn(`  ⚠️  runQuery returned non-array for ${collectionName}:`, JSON.stringify(data).slice(0, 200));
    return [];
  }

  // Filter strictly to the target date (query uses >= so we may get tomorrow too)
  return data
    .filter(item => item.document && (item.document.fields?.timestamp?.stringValue || "").startsWith(dateStr));
}

function deduplicateForDate(docs, locationTag) {
  const targetLoc = locationTag.toLowerCase().trim();
  const filtered = docs.filter(doc => {
    const loc = (doc.fields?.location?.stringValue || "").toLowerCase().trim();
    return loc === targetLoc || loc.includes(targetLoc) || targetLoc.includes(loc);
  });

  const sorted = [...filtered].sort((a, b) =>
    (a.fields?.timestamp?.stringValue || "").localeCompare(b.fields?.timestamp?.stringValue || "")
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

async function syncGymCounts(db, apiCache, daysBack = 1) {
  const dates = [];
  for (let i = 0; i <= daysBack; i++) {
    dates.push(moroccoDateStr(new Date(Date.now() - i * 86400000)));
  }
  console.log(`🔄 Auto-sync for: ${dates.join(", ")}`);

  const admin = require("firebase-admin");

  for (const gym of GYM_SYNC_MAP) {
    for (const dateStr of dates) {
      try {
        // Only fetch docs for THIS date — much cheaper than full collection scan
        const docs = await fetchByDate(gym.collection, dateStr);
        const { unique, raw } = deduplicateForDate(docs, gym.locationTag);

        await db.collection("gym_daily_stats").doc(`${gym.id}_${dateStr}`).set(
          { gym_id: gym.id, date: dateStr, count: unique, rawCount: raw,
            lastSyncedAt: admin.firestore.FieldValue.serverTimestamp() },
          { merge: true }
        );
        console.log(`  ✅ ${gym.id} / ${dateStr}: ${unique} unique (${raw} raw)`);

        // Bust the dashboard cache so next request gets fresh data
        if (apiCache?.dailyStats?.delete) apiCache.dailyStats.delete(gym.id);
      } catch (err) {
        console.error(`  ❌ Sync failed for ${gym.id} / ${dateStr}:`, err.message);
      }
    }
  }
  console.log("✨ Auto-sync done.");
}

// Schedules the next sync at 00:05 Morocco time every night
function scheduleNightlySync(db, apiCache) {
  const moroccoNow = new Date(Date.now() + 3600000);
  const nextRun    = new Date(moroccoNow);
  nextRun.setHours(0, 5, 0, 0);
  if (nextRun <= moroccoNow) nextRun.setDate(nextRun.getDate() + 1);
  const ms = nextRun.getTime() - moroccoNow.getTime();
  console.log(`⏰ Nightly sync scheduled in ${Math.round(ms / 60000)} min (00:05 Morocco)`);
  setTimeout(() => {
    syncGymCounts(db, apiCache, 1).catch(e => console.error("❌ Nightly sync error:", e));
    scheduleNightlySync(db, apiCache); // reschedule for tomorrow
  }, ms);
}

module.exports = { syncGymCounts, scheduleNightlySync };
