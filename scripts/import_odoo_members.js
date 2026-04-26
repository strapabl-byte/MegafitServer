// scripts/import_odoo_members.js
// Imports Odoo Doukkarate members to Firebase Firestore
// Deletes old isArchive=true members first, then imports CSV
// Run: node scripts/import_odoo_members.js
// Requires: serviceAccount.json in the root directory

'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const admin = require('firebase-admin');
const fs    = require('fs');
const path  = require('path');

// ── Firebase Init ────────────────────────────────────────────────────────────
const saPath = path.join(__dirname, '..', 'serviceAccount.json');
const sa = JSON.parse(fs.readFileSync(saPath, 'utf8'));
admin.initializeApp({ credential: admin.credential.cert(sa) });
const db = admin.firestore();

// ── CSV Parsing ──────────────────────────────────────────────────────────────
function parseCSV(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/).filter(l => l.trim());
  const headers = lines[0].split(',').map(h => h.trim());

  return lines.slice(1).map(line => {
    // Handle commas inside quoted fields
    const cols = [];
    let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { inQ = !inQ; }
      else if (c === ',' && !inQ) { cols.push(cur); cur = ''; }
      else { cur += c; }
    }
    cols.push(cur);

    const obj = {};
    headers.forEach((h, i) => {
      obj[h] = (cols[i] || '').replace(/\t/g, ' ').trim(); // clean tabs
    });
    return obj;
  });
}

// ── Status Mapping ───────────────────────────────────────────────────────────
function mapStatus(odooStatus) {
  if (!odooStatus) return 'inactive';
  const s = odooStatus.toLowerCase();
  if (s.includes('active') && !s.includes('expired') && !s.includes('inactive')) return 'active';
  if (s.includes('expired') || s.includes('inactive')) return 'inactive';
  return 'draft';
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const csvPath = path.join(__dirname, '..', '..', 'odoo', 'members_fes_doukkarate.csv');
  console.log(`📂 Reading CSV: ${csvPath}`);
  const rows = parseCSV(csvPath);
  console.log(`📋 Total rows: ${rows.length}`);

  // ── Step 1: Delete old archive members for dokarat ──────────────────────
  console.log('\n🗑️  Deleting old isArchive members for dokarat...');
  const oldSnap = await db.collection('members')
    .where('location', 'in', ['dokkarat fes', 'dokarat', 'dokkarat'])
    .where('isArchive', '==', true)
    .limit(500)
    .get();

  let deletedCount = 0;
  while (!oldSnap.empty) {
    const batch = db.batch();
    oldSnap.docs.forEach(d => batch.delete(d.ref));
    await batch.commit();
    deletedCount += oldSnap.docs.length;
    console.log(`  🗑️  Deleted ${deletedCount} old archive members...`);

    // Check for more
    const more = await db.collection('members')
      .where('location', 'in', ['dokkarat fes', 'dokarat', 'dokkarat'])
      .where('isArchive', '==', true)
      .limit(500)
      .get();
    if (more.empty) break;
  }
  console.log(`✅ Deleted ${deletedCount} old archive members.`);

  // ── Step 2: Import CSV members ───────────────────────────────────────────
  console.log('\n📥 Importing new members from CSV...');

  const BATCH_SIZE = 400;
  let imported = 0;
  let skipped  = 0;

  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    const batch = db.batch();

    for (const row of chunk) {
      const fullName = `${row.firstname || ''} ${row.lastname || ''}`.trim()
        || row.full_name?.replace(/\s+/g, ' ').trim()
        || 'Inconnu';

      if (!fullName || fullName === 'Inconnu') { skipped++; continue; }

      const phone = (row.mobile || row.phone || '').replace(/\s+/g, '');
      const status = mapStatus(row.status);

      // Build the member document
      const doc = {
        fullName,
        firstName:        row.firstname  || '',
        lastName:         row.lastname   || '',
        email:            row.email      || '',
        phone,
        location:         'dokkarat fes',
        status,
        isArchive:        true,   // marks as historical Odoo import
        odooStatus:       row.status || '',
        birthday:         row.x_birthday && row.x_birthday !== '1900-01-01' ? row.x_birthday : null,
        subscriptionStart: row.subs_start || null,
        expiresOn:        row.subs_stop  || null,
        totalPaid:        row.total_paid ? parseFloat(row.total_paid) : 0,
        lastPaymentDate:  row.last_payment_date || null,
        importedFromOdoo: true,
        importedAt:       admin.firestore.FieldValue.serverTimestamp(),
        createdAt:        row.subs_start
          ? admin.firestore.Timestamp.fromDate(new Date(row.subs_start))
          : admin.firestore.FieldValue.serverTimestamp(),
      };

      const ref = db.collection('members').doc(); // auto-ID
      batch.set(ref, doc);
      imported++;
    }

    await batch.commit();
    console.log(`  ✅ Imported ${Math.min(i + BATCH_SIZE, rows.length)} / ${rows.length} members...`);

    // Small delay to avoid rate limiting
    await new Promise(r => setTimeout(r, 300));
  }

  console.log(`\n🎉 Done!`);
  console.log(`   ✅ Imported: ${imported} members`);
  console.log(`   ⏭️  Skipped:  ${skipped} empty rows`);
  process.exit(0);
}

main().catch(err => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});
