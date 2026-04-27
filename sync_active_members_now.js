/**
 * sync_active_members_now.js
 * Fetches ALL active (non-archive) members from Firestore with full pagination
 * and saves them to the local SQLite cache.
 */
const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');
const lc = require('./localCache');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

const GYM_LOCATION_MAP = {
  marjane: ['marjane', 'fes saiss', 'fes marjane'],
  dokarat: ['dokarat', 'dokkarat fes', 'dokkarat'],
  casa1:   ['casa1', 'casa anfa'],
  casa2:   ['casa2', 'lady anfa'],
};

// Paginate through ALL docs (handles > 500)
async function fetchAllPages(gymId) {
  const locations = GYM_LOCATION_MAP[gymId];
  const PAGE = 500;
  let all = [], lastDoc = null;
  while (true) {
    let q = db.collection('members')
      .where('location', 'in', locations)
      .orderBy('__name__')
      .limit(PAGE);
    if (lastDoc) q = q.startAfter(lastDoc);
    const snap = await q.get();
    if (snap.empty) break;
    all = all.concat(snap.docs.map(d => ({ id: d.id, ...d.data() })));
    lastDoc = snap.docs[snap.docs.length - 1];
    console.log(`  [${gymId}] Fetched page: ${all.length} total so far...`);
    if (snap.docs.length < PAGE) break;
  }
  return all;
}

async function run() {
  for (const gymId of Object.keys(GYM_LOCATION_MAP)) {
    try {
      console.log(`\n[${gymId}] Starting full paginated fetch...`);
      const allDocs = await fetchAllPages(gymId);
      
      // Filter: keep ONLY real members (no isArchive flag, or explicitly false)
      const realMembers = allDocs.filter(m => !m.isArchive && !m.importedFromOdoo);
      const archiveCount = allDocs.length - realMembers.length;
      
      console.log(`[${gymId}] Total: ${allDocs.length} | Active: ${realMembers.length} | Archive: ${archiveCount}`);
      
      if (realMembers.length > 0) {
        lc.upsertMembers(gymId, realMembers);
        lc.setMeta(`member_sync_${gymId}`, String(Date.now()));
        console.log(`  ✅ Saved ${realMembers.length} active members to SQLite`);
        realMembers.slice(0, 5).forEach(m => console.log(`     - ${m.fullName} (${m.phone})`));
      }
    } catch (e) {
      console.error(`[${gymId}] Error:`, e.message);
    }
  }

  const total = lc.db.prepare('SELECT COUNT(*) as n FROM members_cache WHERE is_archive = 0').get().n;
  console.log(`\n✅ ALL DONE. Active members in SQLite: ${total}`);
  process.exit(0);
}

run();
