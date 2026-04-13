// auto_sync.js — Optimized: reads daily_unique/daily_total from latest doc (1 read per gym)
const DOOR_PROJECT = "megadoor-b3ccb";
const DOOR_API_KEY = process.env.DOOR_FIREBASE_API_KEY || "AIzaSyBzNbHN_a-4kvI-Z22Ho_pric3mQ7IdiH8";

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
    forceManualCount: true // Device counter for Saiss is unreliable/too high
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
 * FALLBACK: Old method — fetch docs across multiple collections and manually count.
 * Used only when daily_unique is missing or for historical sync.
 */
async function fetchRecentLogsFromCollections(collectionNames, dateStr, limit = 2000) {
  const allDocs = [];
  
  for (const coll of collectionNames) {
    const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT}/databases/(default)/documents:runQuery?key=${DOOR_API_KEY}`;
    const body = {
      structuredQuery: {
        from: [{ collectionId: coll }],
        where: {
          fieldFilter: {
            field: { fieldPath: "timestamp" },
            op: "GREATER_THAN_OR_EQUAL",
            value: { stringValue: dateStr }
          }
        },
        orderBy: [{ field: { fieldPath: "timestamp" }, direction: "DESCENDING" }],
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

async function syncGymCounts(db, apiCache, daysBack = 1) {
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
        let unique, raw;

        if (dateStr === today && !gym.forceManualCount) {
          // ✅ TODAY: Use new fast path — fetch 1 doc, read device counters
          const latestDoc = await fetchLatestDoc(gym.collection, dateStr);

          if (latestDoc) {
            const f = latestDoc.fields || {};
            const loc = (f.location?.stringValue || "").toLowerCase().trim();
            const tags = (gym.locationTags || [gym.locationTag]).map(t => t.toLowerCase().trim());
            const locationOk = tags.some(t => loc === t || loc.includes(t) || t.includes(loc));

            const dailyUnique = parseNum(f.daily_unique);
            const dailyTotal  = parseNum(f.daily_total);

            if (locationOk && dailyUnique !== null && dailyTotal !== null) {
              // New format ✅ — device-computed, 1 read
              unique = dailyUnique;
              raw    = dailyTotal;
              console.log(`  ⚡ ${gym.id} / ${dateStr}: ${unique} unique, ${raw} raw (fast path)`);
            } else {
              // Old format fallback — manual count across one or more collections
              console.log(`  ⚠️  ${gym.id}: daily_unique missing or location mismatch, using fallback count`);
              const allDocs = await fetchRecentLogsFromCollections(gym.collections || [gym.collection], dateStr);
              ({ unique, raw } = deduplicateForDate(allDocs, gym.locationTags || [gym.locationTag], dateStr));
              console.log(`  📊 ${gym.id} / ${dateStr}: ${unique} unique, ${raw} raw (fallback)`);
            }
          } else {
            unique = 0; raw = 0;
            console.log(`  ℹ️  ${gym.id}: No entries today yet`);
          }
        } else {
          // 📅 PAST DAYS: Use old method (daily_unique not reliable for past docs)
          const allDocs = await fetchRecentLogsFromCollections(gym.collections || [gym.collection], dateStr);
          ({ unique, raw } = deduplicateForDate(allDocs, gym.locationTags || [gym.locationTag], dateStr));
          console.log(`  📅 ${gym.id} / ${dateStr}: ${unique} unique, ${raw} raw (historical)`);
        }

        await db.collection("gym_daily_stats").doc(`${gym.id}_${dateStr}`).set(
          {
            gym_id: gym.id,
            date:   dateStr,
            count:  unique,
            rawCount: raw,
            lastSyncedAt: admin.firestore.FieldValue.serverTimestamp()
          },
          { merge: true }
        );

        // Invalidate the RAM cache so next request gets fresh data from Firestore
        if (apiCache?.dailyStats) delete apiCache.dailyStats[gym.id];
      } catch (err) {
        console.error(`  ❌ Sync failed for ${gym.id} / ${dateStr}:`, err.message);
      }
    }
  }
  console.log("✨ Auto-sync complete.");
}

/**
 * Schedule: hourly during the day (08:00–23:00 Morocco) + nightly at 00:05
 */
function scheduleNightlySync(db, apiCache) {
  // ── Nightly full sync at 00:05 Morocco ──────────────────────────────────
  const moroccoNow = new Date(Date.now() + 3600000);
  const nextNight  = new Date(moroccoNow);
  nextNight.setHours(0, 5, 0, 0);
  if (nextNight <= moroccoNow) nextNight.setDate(nextNight.getDate() + 1);
  const msToNight = nextNight.getTime() - moroccoNow.getTime();

  console.log(`⏰ Nightly sync scheduled in ${Math.round(msToNight / 60000)} min (00:05 Morocco)`);
  setTimeout(() => {
    syncGymCounts(db, apiCache, 7).catch(e => console.error("❌ Nightly sync error:", e));
    scheduleNightlySync(db, apiCache); // reschedule for next night
  }, msToNight);

  // ── Hourly today-only sync ───────────────────────────────────────────────
  // Runs every 60 minutes — uses 1 read per gym (fast path)
  setInterval(() => {
    const h = new Date(Date.now() + 3600000).getHours(); // Morocco hour
    if (h >= 7 && h <= 23) { // Only during gym hours
      console.log(`⏱️  Hourly sync triggered (${h}:xx Morocco)`);
      syncGymCounts(db, apiCache, 0).catch(e => console.error("❌ Hourly sync error:", e));
    }
  }, 60 * 60 * 1000); // every 60 minutes

  console.log(`⏱️  Hourly sync active (every 60min, 07:00–23:00 Morocco)`);
}

module.exports = { syncGymCounts, scheduleNightlySync };
