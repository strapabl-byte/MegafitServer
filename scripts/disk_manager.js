'use strict';
/**
 * disk_manager.js — Render Disk Admin Tool
 * ==========================================
 * Manages the SQLite persistent disk on Render.
 * Run locally: node scripts/disk_manager.js [command]
 *
 * Commands:
 *   stats          → Show member and entry counts per gym
 *   export-members → Export all members to members_export.json
 *   import-members → Import members from a JSON file into SQLite
 *   clear-sync     → Reset sync flags (forces re-seed on next startup)
 *   prune-archive  → Remove is_archive=1 members older than 2 years
 *   help           → Show this help
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

const DATA_DIR = fs.existsSync('/var/data') ? '/var/data' : path.join(__dirname, '..');
const DB_PATH  = process.env.DB_PATH || path.join(DATA_DIR, 'megafit_cache.db');

if (!fs.existsSync(DB_PATH)) {
  console.error(`❌ No SQLite database found at: ${DB_PATH}`);
  console.error('   Make sure the Render disk is mounted or run the server first to create it.');
  process.exit(1);
}

const db = new Database(DB_PATH, { readonly: false });
const cmd = process.argv[2] || 'help';

// ──────────────────────────────────────────────────────────────────────────────
// STATS
// ──────────────────────────────────────────────────────────────────────────────
function cmdStats() {
  console.log('\n📊 DISK STATS\n' + '─'.repeat(50));
  console.log(`📍 DB Path: ${DB_PATH}`);

  const statBytes = fs.statSync(DB_PATH);
  console.log(`💾 DB Size: ${(statBytes.size / 1024 / 1024).toFixed(2)} MB\n`);

  // Members per gym
  const gyms = db.prepare(`SELECT gym_id, COUNT(*) as cnt FROM members_cache GROUP BY gym_id ORDER BY cnt DESC`).all();
  console.log('👥 Members per gym:');
  let totalMembers = 0;
  gyms.forEach(g => { console.log(`   ${g.gym_id.padEnd(12)} → ${g.cnt}`); totalMembers += g.cnt; });
  console.log(`   ${'TOTAL'.padEnd(12)} → ${totalMembers}\n`);

  // Archive vs active
  const archive = db.prepare(`SELECT COUNT(*) as cnt FROM members_cache WHERE is_archive = 1`).get();
  const active  = db.prepare(`SELECT COUNT(*) as cnt FROM members_cache WHERE is_archive = 0 OR is_archive IS NULL`).get();
  console.log(`   Active: ${active.cnt}  |  Archive: ${archive.cnt}\n`);

  // Entries
  const entryRow  = db.prepare(`SELECT COUNT(*) as cnt FROM entries`).get();
  const statsRow  = db.prepare(`SELECT COUNT(*) as cnt FROM daily_stats WHERE count > 0`).get();
  const regRow    = db.prepare(`SELECT COUNT(*) as cnt FROM register_cache`).get();
  const recruRow  = db.prepare(`SELECT COUNT(*) as cnt FROM recruitment_applications`).get();
  console.log('📂 Other tables:');
  console.log(`   door entries    → ${entryRow.cnt}`);
  console.log(`   daily_stats     → ${statsRow.cnt} days with data`);
  console.log(`   register_cache  → ${regRow.cnt} payment entries`);
  console.log(`   recruitment CVs → ${recruRow.cnt}\n`);

  // Sync metadata
  const metaRows = db.prepare(`SELECT key, value FROM meta ORDER BY key`).all();
  console.log('🔖 Sync metadata:');
  metaRows.forEach(m => console.log(`   ${m.key.padEnd(30)} → ${m.value}`));
  console.log('');
}

// ──────────────────────────────────────────────────────────────────────────────
// EXPORT MEMBERS
// ──────────────────────────────────────────────────────────────────────────────
function cmdExportMembers() {
  const outPath = path.join(__dirname, '..', 'members_export.json');
  const rows = db.prepare(`SELECT * FROM members_cache ORDER BY gym_id, full_name`).all();
  fs.writeFileSync(outPath, JSON.stringify(rows, null, 2), 'utf8');
  console.log(`✅ Exported ${rows.length} members → ${outPath}`);
}

// ──────────────────────────────────────────────────────────────────────────────
// IMPORT MEMBERS
// ──────────────────────────────────────────────────────────────────────────────
function cmdImportMembers(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    console.error('❌ Usage: node scripts/disk_manager.js import-members <path-to-file.json>');
    process.exit(1);
  }
  const members = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const stmt = db.prepare(`
    INSERT INTO members_cache (id, gym_id, full_name, phone, plan, expires_on, status, birthday, email, is_archive, synced_at)
    VALUES (@id, @gym_id, @full_name, @phone, @plan, @expires_on, @status, @birthday, @email, @is_archive, @synced_at)
    ON CONFLICT(id, gym_id) DO UPDATE SET
      full_name  = excluded.full_name,
      phone      = excluded.phone,
      plan       = excluded.plan,
      expires_on = excluded.expires_on,
      status     = excluded.status,
      is_archive = excluded.is_archive,
      synced_at  = excluded.synced_at
  `);
  const upsertAll = db.transaction((rows) => rows.forEach(m => {
    stmt.run({
      id: m.id || m.firebaseId || '',
      gym_id: m.gym_id || m.gymId || 'dokarat',
      full_name: m.full_name || m.fullName || '',
      phone: m.phone || null,
      plan: m.plan || null,
      expires_on: m.expires_on || m.expiresOn || null,
      status: m.status || null,
      birthday: m.birthday || null,
      email: m.email || null,
      is_archive: m.is_archive || m.isArchive ? 1 : 0,
      synced_at: new Date().toISOString(),
    });
  }));
  upsertAll(members);
  console.log(`✅ Imported/updated ${members.length} members into SQLite.`);
}

// ──────────────────────────────────────────────────────────────────────────────
// CLEAR SYNC FLAGS (forces re-seed on next server start)
// ──────────────────────────────────────────────────────────────────────────────
function cmdClearSync() {
  db.prepare(`DELETE FROM meta WHERE key LIKE 'member_sync_%' OR key = 'archive_members_synced' OR key = 'last_gap_fill'`).run();
  console.log('✅ Sync flags cleared. The server will re-seed from the JSON file on next startup.');
}

// ──────────────────────────────────────────────────────────────────────────────
// PRUNE ARCHIVE MEMBERS older than N years
// ──────────────────────────────────────────────────────────────────────────────
function cmdPruneArchive(years = 2) {
  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - years);
  const cutoffStr = cutoff.toISOString().split('T')[0];
  const result = db.prepare(`
    DELETE FROM members_cache
    WHERE is_archive = 1
      AND (expires_on < ? OR expires_on IS NULL)
  `).run(cutoffStr);
  console.log(`🗑️  Pruned ${result.changes} archive members expired before ${cutoffStr}.`);
}

// ──────────────────────────────────────────────────────────────────────────────
// ROUTER
// ──────────────────────────────────────────────────────────────────────────────
switch (cmd) {
  case 'stats':           cmdStats(); break;
  case 'export-members':  cmdExportMembers(); break;
  case 'import-members':  cmdImportMembers(process.argv[3]); break;
  case 'clear-sync':      cmdClearSync(); break;
  case 'prune-archive':   cmdPruneArchive(parseInt(process.argv[3]) || 2); break;
  case 'help':
  default:
    console.log(`
📦 disk_manager.js — Render Disk Admin Tool
────────────────────────────────────────────
  node scripts/disk_manager.js stats
    Show member/entry counts and sync metadata

  node scripts/disk_manager.js export-members
    Export all members to members_export.json

  node scripts/disk_manager.js import-members <file.json>
    Import/update members from a JSON file

  node scripts/disk_manager.js clear-sync
    Reset sync flags (forces re-seed on next startup)

  node scripts/disk_manager.js prune-archive [years]
    Remove archive members expired N+ years ago (default: 2)
`);
}

db.close();
