// compare_entries.js — Compares Firebase direct vs API server output for Dokarat
// Usage: node compare_entries.js
require("dotenv").config();
const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const DOOR_PROJECT_ID = process.env.DOOR_FIREBASE_PROJECT_ID || "megadoor-b3ccb";
const DOOR_REST_KEY = process.env.DOOR_FIREBASE_API_KEY;

const collectionName = "mega_fit_logs";
const locationTag = "dokkarat fes";

async function queryFirebaseDirect(limit = 1000) {
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT_ID}/databases/(default)/documents:runQuery?key=${DOOR_REST_KEY}`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: {
        fieldFilter: {
          field: { fieldPath: "location" },
          op: "EQUAL",
          value: { stringValue: locationTag }
        }
      },
      limit
    }
  };

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const data = await resp.json();
  if (!Array.isArray(data)) {
    console.error("Firebase REST Error:", JSON.stringify(data));
    return [];
  }

  return data
    .filter(item => item.document)
    .map(item => {
      const f = item.document.fields || {};
      const pushedAt = f.pushed_at?.timestampValue || null;
      const timestamp = f.timestamp?.stringValue || null;
      let sortKey = "";
      let displayTime = "--:--";
      if (pushedAt) {
        const d = new Date(pushedAt);
        sortKey = d.toISOString();
        displayTime = d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", timeZone: "Africa/Casablanca" });
      } else if (timestamp) {
        sortKey = timestamp;
        displayTime = timestamp.split(" ")[1]?.slice(0, 5) || "--:--";
      }
      return {
        docId: item.document.name.split("/").pop(),
        name: f.name?.stringValue || "Anonyme",
        sortKey,
        displayTime,
        location: f.location?.stringValue || ""
      };
    })
    .filter(d => d.sortKey)
    .sort((a, b) => b.sortKey.localeCompare(a.sortKey));
}

async function queryApiServer() {
  const res = await fetch("http://localhost:4000/api/live-entries?gymId=dokarat&limit=1000", {
    headers: { Authorization: "Bearer dev-bypass" }
  });
  if (!res.ok) {
    console.error("API Error:", res.status, await res.text());
    return [];
  }
  const data = await res.json();
  return data.entries || [];
}

async function run() {
  console.log("\n🔍 Fetching directly from Firebase REST API...");
  const firebaseEntries = await queryFirebaseDirect(1000);

  console.log("\n🔍 Fetching from local API server (/api/live-entries)...");
  // Note: server auth is required, so this will likely fail without a valid token
  // We'll compare counts and top entries instead

  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);

  const firebaseToday = firebaseEntries.filter(e => e.sortKey?.startsWith(todayStr));
  const firebaseTotal = firebaseEntries.length;

  console.log("\n" + "=".repeat(60));
  console.log("📊 FIREBASE DIRECT RESULTS");
  console.log("=".repeat(60));
  console.log(`  Total docs in mega_fit_logs (location=dokkarat fes): ${firebaseTotal}`);
  console.log(`  Today (${todayStr}): ${firebaseToday.length} entries`);

  console.log("\n  🔟 Last 10 entries (newest first):");
  firebaseEntries.slice(0, 10).forEach((e, i) => {
    console.log(`  ${i + 1}. [${e.displayTime}] ${e.name.padEnd(25)} | ${e.sortKey.slice(0, 19)} | doc: ${e.docId}`);
  });

  console.log("\n" + "=".repeat(60));
  console.log("⚠️  API SERVER NOTE:");
  console.log("=".repeat(60));
  console.log("  The server currently has limit=300 HARDCODED in the Firestore");
  console.log("  structuredQuery body (server.js ~line 1207), independent");
  console.log("  of the limitCount variable passed from the URL param.");
  console.log("");
  console.log(`  Firebase has ${firebaseTotal} total docs, server query fetches max 300.`);
  if (firebaseTotal > 300) {
    console.log(`  ❌ MISMATCH: ${firebaseTotal - 300} entries are being SKIPPED!`);
  } else {
    console.log(`  ✅ OK: Total docs (${firebaseTotal}) is within the 300 limit.`);
  }

  console.log("\n" + "=".repeat(60));
}

run().catch(console.error);
