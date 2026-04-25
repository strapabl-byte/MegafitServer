'use strict';
// diagnose_members.js
// Checks the state of specific members in Firestore + SQLite
require('dotenv').config();
const admin = require('firebase-admin');
const path  = require('path');
const fs    = require('fs');
const lc    = require('./localCache');

const localPath = path.join(__dirname, 'serviceAccount.json');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(require(localPath)) });
}
const db = admin.firestore();

const SEARCH_NAMES = ['Benjelloun', 'OUMAIMA', 'DIOURI'];

async function run() {
  console.log('\n=== FIRESTORE: pending_members ===\n');
  const pendSnap = await db.collection('pending_members').get();
  for (const doc of pendSnap.docs) {
    const d = doc.data();
    const fullName = `${d.prenom||''} ${d.nom||''}`.trim();
    if (SEARCH_NAMES.some(n => fullName.toLowerCase().includes(n.toLowerCase()))) {
      console.log(`[PENDING] ${fullName}`);
      console.log(`  id: ${doc.id}`);
      console.log(`  status: ${d.status}`);
      console.log(`  memberId: ${d.memberId || '❌ NONE'}`);
      console.log(`  gymId: ${d.gymId}`);
      console.log(`  contractNumber: ${d.contractNumber}`);
      console.log(`  createdAt: ${d.createdAt?._seconds ? new Date(d.createdAt._seconds*1000).toLocaleString() : '?'}`);
      console.log('');
    }
  }

  console.log('\n=== FIRESTORE: members collection ===\n');
  const memSnap = await db.collection('members').get();
  for (const doc of memSnap.docs) {
    const d = doc.data();
    const fullName = d.fullName || '';
    if (SEARCH_NAMES.some(n => fullName.toLowerCase().includes(n.toLowerCase()))) {
      console.log(`[MEMBER] ${fullName}`);
      console.log(`  id: ${doc.id}`);
      console.log(`  location: ${d.location}`);
      console.log(`  status: ${d.status || '(no status field)'}`);
      console.log(`  expiresOn: ${d.expiresOn}`);
      console.log(`  plan: ${d.plan}`);
      console.log(`  createdAt: ${d.createdAt?._seconds ? new Date(d.createdAt._seconds*1000).toLocaleString() : '?'}`);
      console.log('');
    }
  }

  console.log('\n=== SQLITE: members_cache ===\n');
  const sqlRows = lc.db.prepare(`
    SELECT id, gym_id, full_name, status, expires_on, synced_at
    FROM members_cache
    WHERE ${SEARCH_NAMES.map(() => 'LOWER(full_name) LIKE ?').join(' OR ')}
  `).all(...SEARCH_NAMES.map(n => `%${n.toLowerCase()}%`));
  
  if (sqlRows.length === 0) {
    console.log('❌ NOT FOUND in SQLite members_cache — this is why they are invisible in the Members page!');
  } else {
    sqlRows.forEach(r => {
      console.log(`[SQLite] ${r.full_name} | gym: ${r.gym_id} | status: ${r.status} | expires: ${r.expires_on} | synced: ${r.synced_at}`);
    });
  }

  console.log('\n=== SQLITE: register_cache (today) ===\n');
  const today = new Date().toISOString().slice(0, 10);
  const regRows = lc.db.prepare(`
    SELECT id, gym_id, date, nom, prix, commercial
    FROM register_cache
    WHERE date = ? AND (${SEARCH_NAMES.map(() => 'LOWER(nom) LIKE ?').join(' OR ')})
  `).all(today, ...SEARCH_NAMES.map(n => `%${n.toLowerCase()}%`));

  if (regRows.length === 0) {
    console.log(`❌ NOT FOUND in register_cache for today (${today})`);
  } else {
    regRows.forEach(r => console.log(`[Register] ${r.nom} | ${r.prix} DH | ${r.gym_id} | ${r.date}`));
  }

  console.log('\n─────────────────────────────────────────────\n');
  process.exit(0);
}

run().catch(err => { console.error('Fatal:', err); process.exit(1); });
