'use strict';
const express = require('express');
const admin = require('firebase-admin');
const { getFirestore } = require('firebase-admin/firestore');
const lc = require('../localCache');
const path = require('path');
const fs = require('fs');

// Initialize secondary Firebase Admin app for recruitment
let recruteApp;
let dbRecrute;

try {
  const serviceAccountPath = path.join(__dirname, '..', 'serviceAccount_recrute.json');
  if (fs.existsSync(serviceAccountPath)) {
    const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));
    
    // Check if app already exists to avoid "app already exists" error on hot-reload
    if (admin.apps.some(app => app.name === 'recrute')) {
      recruteApp = admin.app('recrute');
    } else {
      recruteApp = admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      }, 'recrute');
    }

    // 🔥 CORRECT WAY for Named Databases in Admin SDK:
    // We target the 'default' database ID as seen in the user's config
    dbRecrute = getFirestore(recruteApp, 'default');
    console.log('🚀 Recruitment Admin initialized with database: default');
  } else {
    console.warn('⚠️ Recruitment service account not found. Sync disabled.');
  }
} catch (err) {
  console.error('❌ Failed to initialize Recruitment Admin:', err.message);
}

module.exports = function(deps) {
  const router = express.Router();
  const { verifyAzureToken } = require('../middleware/auth');

  router.get('/api/recruitment/applications', verifyAzureToken, async (req, res) => {
    try {
      if (!dbRecrute) {
        const cached = lc.getRecruitmentApplications();
        return res.json({ ok: true, count: cached.length, applications: cached, warning: 'Recruitment DB not available' });
      }

      const lastSync = lc.getLastRecruitmentSync();
      let queryRef = dbRecrute.collection('recruitment_applications');

      if (!lastSync) {
        console.log('[RECRUITMENT] First sync: fetching all applications...');
        queryRef = queryRef.orderBy('createdAt', 'desc').limit(500);
      } else {
        const lastSyncDate = new Date(lastSync);
        console.log(`[RECRUITMENT] Incremental sync since: ${lastSyncDate.toISOString()}`);
        queryRef = queryRef.where('createdAt', '>', admin.firestore.Timestamp.fromDate(lastSyncDate))
                           .orderBy('createdAt', 'desc');
      }

      const snapshot = await queryRef.get();
      const newApps = [];
      snapshot.forEach((doc) => {
        const data = doc.data();
        newApps.push({
          id: doc.id,
          ...data,
          createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : 
                     (data.createdAt?._seconds ? new Date(data.createdAt._seconds * 1000).toISOString() : data.createdAt)
        });
      });

      if (newApps.length > 0) {
        lc.upsertRecruitmentApplications(newApps);
        const newestDate = newApps.reduce((latest, current) => {
          return new Date(current.createdAt) > new Date(latest) ? current.createdAt : latest;
        }, newApps[0].createdAt);
        lc.setLastRecruitmentSync(newestDate);
        console.log(`✅ [RECRUITMENT] Synced ${newApps.length} new applications.`);
      }

      const allApps = lc.getRecruitmentApplications();
      res.json({ ok: true, count: allApps.length, applications: allApps });

    } catch (err) {
      console.error('❌ [RECRUITMENT] Sync error:', err.message);
      const cached = lc.getRecruitmentApplications();
      res.json({ ok: true, count: cached.length, applications: cached, error: err.message });
    }
  });

  return router;
};
