'use strict';
/**
 * generate_member_seed.js
 * ───────────────────────
 * Exports all members from Firestore into a JSON seed file.
 * This file will be committed to GitHub so the Render server can 
 * populate its SQLite cache with ZERO Firestore reads.
 */
require('dotenv').config();
const admin = require('firebase-admin');
const fs    = require('fs');
const path  = require('path');

const serviceAccountPath = path.join(__dirname, '..', 'serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(require(serviceAccountPath))
  });
}
const db = admin.firestore();

async function main() {
  console.log('🚀 Exporting members for JSON Seed...');

  const snapshot = await db.collection('members').get();
  console.log(`✅ Fetched ${snapshot.size} members.`);

  const members = snapshot.docs.map(doc => {
    const d = doc.data();
    return {
      id: doc.id,
      fullName: d.fullName || '',
      phone: d.phone || '',
      cin: d.cin || '',
      email: d.email || '',
      birthday: d.birthday || '',
      adresse: d.adresse || '',
      ville: d.ville || '',
      expiresOn: d.expiresOn || null,
      bonus3Months: d.bonus3Months || false,
      location: d.location || d.gymId || 'dokarat',
      photo: d.photo || null,
      status: d.status || '',
      isArchive: d.isArchive || d.importedFromOdoo || false
    };
  });

  const outputPath = path.join(__dirname, '..', 'seed_members_all.json');
  fs.writeFileSync(outputPath, JSON.stringify(members, null, 2));

  console.log(`\n✨ Done! Seed file created at: ${outputPath}`);
  console.log(`📦 File size: ${(fs.statSync(outputPath).size / 1024 / 1024).toFixed(2)} MB`);
  console.log('⚠️  Make sure to update server.js to point to this new seed_members_all.json file.');
  
  process.exit(0);
}

main().catch(err => {
  console.error('❌ Export Failed:', err);
  process.exit(1);
});
