'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const admin = require('firebase-admin');
const serviceAccount = require('../serviceAccount.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const lc = require('../localCache');

async function run() {
  console.log('Fetching eligible members from SQLite cache...');
  const rows = lc.db.prepare(`
    SELECT id, full_name, expires_on
    FROM members_cache
    WHERE gym_id = 'dokarat'
      AND (
        (created_at IS NOT NULL AND created_at < '2025-10-31') OR
        (period_from IS NOT NULL AND period_from < '2025-10-31')
      )
      AND expires_on >= '2025-08-01'
  `).all();

  const eligibleIds = rows.filter(r => r.expires_on && !r.expires_on.startsWith('19')).map(r => r.id);
  console.log(`Found ${eligibleIds.length} eligible members to update.`);

  if (eligibleIds.length === 0) {
    console.log('No members to update.');
    return;
  }

  let updatedCount = 0;
  let errors = 0;

  for (const id of eligibleIds) {
    try {
      const ref = db.collection('members').doc(id);
      const snap = await ref.get();
      if (!snap.exists) continue;

      const member = snap.data();
      if (!member.expiresOn || typeof member.expiresOn !== 'string') continue;

      // Add 3 months to expiresOn
      const expDate = new Date(member.expiresOn);
      if (isNaN(expDate)) continue;

      expDate.setMonth(expDate.getMonth() + 3);
      const newExpiresOn = expDate.toISOString().slice(0, 10); // YYYY-MM-DD

      // Update Firestore
      await ref.update({
        expiresOn: newExpiresOn,
        bonus3Months: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Fetch the updated doc to sync to SQLite
      const updatedSnap = await ref.get();
      const updatedData = { id: updatedSnap.id, ...updatedSnap.data() };
      
      // Update SQLite Cache
      lc.upsertMembers('dokarat', [updatedData]);
      
      updatedCount++;
      process.stdout.write(`\rUpdated ${updatedCount}/${eligibleIds.length} (${member.fullName})`);
    } catch (err) {
      console.error(`\nError updating member ${id}:`, err);
      errors++;
    }
  }

  console.log(`\n\n✅ Update Complete!`);
  console.log(`Successfully updated: ${updatedCount}`);
  console.log(`Errors: ${errors}`);
  process.exit(0);
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
