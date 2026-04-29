const db = require('better-sqlite3')('megafit_cache.db');

// Force re-identification for all entries currently cached as 'expired'
// by backdating their cached_at so the 24h TTL triggers a fresh lookup
const r1 = db.prepare("UPDATE smart_identity_cache SET cached_at='2000-01-01' WHERE id_status='expired'").run();
console.log('✅ Marked stale (will re-identify on next scan):', r1.changes, 'entries');

// Also fully delete ZINEB KAMAR so it re-identifies immediately
const r2 = db.prepare("DELETE FROM smart_identity_cache WHERE LOWER(matched_name) LIKE '%zineb%'").run();
console.log('✅ Deleted ZINEB cache entries:', r2.changes);
