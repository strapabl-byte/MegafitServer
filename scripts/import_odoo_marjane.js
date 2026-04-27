// scripts/import_odoo_marjane.js
// Imports Fès Marjane (Fès Saiss) members from Odoo CSV to Firebase Firestore
// AND regenerates imported_members.json for the static dashboard archive.
// Run: node scripts/import_odoo_marjane.js
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
    headers.forEach((h, i) => { obj[h] = (cols[i] || '').replace(/\t/g, ' ').trim(); });
    return obj;
  });
}

// ── Status Mapping ───────────────────────────────────────────────────────────
function mapStatus(odooStatus) {
  if (!odooStatus) return 'inactive';
  const s = odooStatus.toLowerCase();
  if (s.includes('future')) return 'active'; // future subs still count
  if (s.includes('active') && !s.includes('expired') && !s.includes('inactive')) return 'active';
  if (s.includes('expired') || s.includes('inactive')) return 'inactive';
  return 'draft';
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const csvPath = path.join(__dirname, '..', '..', 'odoo', 'members_fes_marjane.csv');
  console.log(`📂 Reading CSV: ${csvPath}`);
  const rows = parseCSV(csvPath);
  console.log(`📋 Total rows: ${rows.length}`);

  // ── Step 1: Delete old archive members for marjane ──────────────────────
  console.log('\n🗑️  Deleting old isArchive members for marjane...');
  let deletedCount = 0;
  let hasMore = true;
  while (hasMore) {
    const oldSnap = await db.collection('members')
      .where('location', '==', 'marjane')
      .where('isArchive', '==', true)
      .limit(400)
      .get();
    if (oldSnap.empty) { hasMore = false; break; }
    const batch = db.batch();
    oldSnap.docs.forEach(d => batch.delete(d.ref));
    await batch.commit();
    deletedCount += oldSnap.docs.length;
    console.log(`  🗑️  Deleted ${deletedCount} old archive members...`);
    if (oldSnap.docs.length < 400) hasMore = false;
  }
  console.log(`✅ Deleted ${deletedCount} old archive marjane members.`);

  // ── Step 2: Import CSV members to Firestore ──────────────────────────────
  console.log('\n📥 Importing Fès Marjane members from CSV...');
  const BATCH_SIZE = 400;
  let imported = 0;
  let skipped  = 0;
  const jsonOutput = []; // for static file

  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE);
    const batch = db.batch();

    for (const row of chunk) {
      const fullName = `${row.firstname || ''} ${row.lastname || ''}`.replace(/\s+/g, ' ').trim()
        || row.full_name?.replace(/\s+/g, ' ').trim()
        || 'Inconnu';

      if (!fullName || fullName === 'Inconnu') { skipped++; continue; }

      const phone = (row.mobile || row.phone || '').replace(/\s+/g, '');
      const status = mapStatus(row.status);
      const nameParts = fullName.split(' ');
      const firstName = nameParts[0] || '';
      const surname   = nameParts.slice(1).join(' ') || '';

      const doc = {
        fullName,
        firstName: row.firstname || firstName,
        lastName:  row.lastname  || surname,
        name:      firstName,
        surname,
        email:     row.email || '',
        phone,
        location:  'marjane',
        status,
        isArchive: true,
        importedFromOdoo: true,
        odooStatus: row.status || '',
        birthday:   row.x_birthday && row.x_birthday !== '1900-01-01' ? row.x_birthday : null,
        subscriptionStart: row.subs_start || null,
        expiresOn:  row.subs_stop  || null,
        periodFrom: row.subs_start || null,
        periodTo:   row.subs_stop  || null,
        totalPaid:  row.total_paid ? parseFloat(row.total_paid) : 0,
        lastPaymentDate: row.last_payment_date || null,
        importedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdAt:  row.subs_start
          ? admin.firestore.Timestamp.fromDate(new Date(row.subs_start))
          : admin.firestore.FieldValue.serverTimestamp(),
      };

      const ref = db.collection('members').doc();
      batch.set(ref, doc);

      // Build JSON entry for static file (using auto-id placeholder)
      jsonOutput.push({
        id:         `legacy-marjane-${imported}`,
        fullName,
        name:       firstName,
        surname,
        phone,
        email:      row.email || '',
        location:   'marjane',
        status,
        totalPaid:  row.total_paid || '0.0',
        subFee:     '0.0',
        createdAt:  row.subs_start || '',
        subStart:   row.subs_start || '',
        expiresOn:  row.subs_stop  || '',
        birthday:   row.x_birthday || '',
        periodFrom: row.subs_start || '',
        periodTo:   row.subs_stop  || '',
        isImported: true,
        isArchive:  true,
        odooStatus: row.status || '',
      });

      imported++;
    }

    await batch.commit();
    console.log(`  ✅ Imported ${Math.min(i + BATCH_SIZE, rows.length)} / ${rows.length} members...`);
    await new Promise(r => setTimeout(r, 300));
  }

  console.log(`\n🎉 Firestore import done!`);
  console.log(`   ✅ Imported: ${imported} members`);
  console.log(`   ⏭️  Skipped:  ${skipped} empty rows`);

  // ── Step 3: Merge with existing imported_members.json ─────────────────────
  console.log('\n📦 Merging into imported_members.json...');
  const jsonPath = path.join(__dirname, '..', '..', 'megafit-dashboard3', 'src', 'data', 'imported_members.json');

  let existingMembers = [];
  try {
    const raw = fs.readFileSync(jsonPath, 'utf8');
    existingMembers = JSON.parse(raw);
    console.log(`   📂 Loaded ${existingMembers.length} existing members from JSON`);
  } catch (e) {
    console.warn(`   ⚠️  Could not read existing JSON, starting fresh: ${e.message}`);
  }

  // Remove old marjane archive entries
  const withoutOldMarjane = existingMembers.filter(m => m.location !== 'marjane' || !m.isArchive);
  console.log(`   🗑️  Removed ${existingMembers.length - withoutOldMarjane.length} old marjane archive entries`);

  // Append new marjane entries
  const merged = [...withoutOldMarjane, ...jsonOutput];
  console.log(`   ✅ Total members in JSON: ${merged.length}`);

  fs.writeFileSync(jsonPath, JSON.stringify(merged, null, 2), 'utf8');
  console.log(`   💾 Saved to: ${jsonPath}`);

  process.exit(0);
}

main().catch(err => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});
