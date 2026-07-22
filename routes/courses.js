'use strict';
// routes/courses.js — Courses, Coaches, Reservations, Bilans

const { Router } = require('express');
const crypto = require('crypto');
const { verifyAzureToken } = require('../middleware/auth');

module.exports = function coursesRouter({ db, admin }) {
  const router = Router();

  // ── Courses ───────────────────────────────────────────────────────────────
  async function getCoursesWithCounts(weekday, gymId) {
    let query = db.collection('courses');
    if (gymId && gymId !== 'all') query = query.where('gymId', '==', gymId);

    const snap = await query.get();
    return Promise.all(snap.docs.map(async (doc) => {
      const data = doc.data();
      const resSnap = await db.collection('reservations').where('sessionId', '==', doc.id).where('weekday', '==', weekday).where('status', '==', 'reserved').get();
      if (data.reserved !== resSnap.size) await doc.ref.update({ reserved: resSnap.size, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      return { id: doc.id, ...data, reserved: resSnap.size };
    }));
  }

  router.get('/api/courses', verifyAzureToken, async (req, res) => {
    try {
      const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();

      const isAdmin = req.isAdmin;
      let gymId = req.query.gymId;

      // 🔒 SECURITY: Restrict non-admins to their assigned gym
      if (!isAdmin) {
        const assigned = req.assignedGyms?.[0];
        if (assigned && assigned !== 'all') {
          gymId = assigned;
        } else {
          gymId = 'none';
        }
      } else if (!gymId) {
        gymId = 'all';
      }
      res.json(await getCoursesWithCounts(weekday, gymId));
    } catch (err) { console.error('Failed to fetch courses:', err); res.status(500).json({ error: 'Failed to fetch courses' }); }
  });

  router.get('/public/courses', async (req, res) => {
    try {
      const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
      res.json(await getCoursesWithCounts(weekday));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch public courses' }); }
  });

  router.post('/api/courses', verifyAzureToken, async (req, res) => {
    try {
      const { title, coach, days, time, capacity, gymId } = req.body;
      if (!title || !coach || !days || !time || !gymId) return res.status(400).json({ error: 'Missing fields' });

      // Security check
      if (!req.hasAccessToGym(gymId)) return res.status(403).json({ error: 'Unauthorized for this gym' });

      const docRef = await db.collection('courses').add({
        title, coach, days, time, capacity: Number(capacity) || 20,
        gymId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: req.user?.preferred_username || 'Admin'
      });
      const snap = await docRef.get();
      const courseData = { id: docRef.id, ...snap.data(), reserved: 0 };
      
      // Update SQLite courses_cache
      try {
        const lc = require('../localCache');
        if (lc && typeof lc.upsertCourses === 'function') {
          lc.upsertCourses([courseData]);
        }
      } catch (cErr) {
        console.warn('[COURSES CACHE] upsert failed on creation:', cErr.message);
      }

      res.json(courseData);
    } catch (err) { res.status(500).json({ error: 'Failed to create course' }); }
  });

  router.put('/api/courses/:id', verifyAzureToken, async (req, res) => {
    try {
      const allowed = ['title', 'coach', 'days', 'time', 'capacity'];
      const update = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, k === 'capacity' ? Number(req.body[k]) : req.body[k]]));
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      const ref = db.collection('courses').doc(req.params.id);
      await ref.update(update);
      const snap = await ref.get();
      const updatedData = { id: snap.id, ...snap.data() };

      // Update SQLite courses_cache
      try {
        const lc = require('../localCache');
        if (lc && typeof lc.upsertCourses === 'function') {
          lc.upsertCourses([updatedData]);
        }
      } catch (cErr) {
        console.warn('[COURSES CACHE] upsert failed on update:', cErr.message);
      }

      res.json(updatedData);
    } catch (err) { res.status(500).json({ error: 'Failed to update course' }); }
  });

  router.delete('/api/courses/:id', verifyAzureToken, async (req, res) => {
    try {
      await db.collection('courses').doc(req.params.id).delete();

      // Delete from SQLite courses_cache
      try {
        const lc = require('../localCache');
        if (lc && lc.db) {
          lc.db.prepare('DELETE FROM courses_cache WHERE id=?').run(req.params.id);
        }
      } catch (cErr) {
        console.warn('[COURSES CACHE] delete failed:', cErr.message);
      }

      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete course' }); }
  });

  router.get('/api/courses/:id/reservations', verifyAzureToken, async (req, res) => {
    try {
      const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
      const snap = await db.collection('reservations').where('sessionId', '==', req.params.id).where('weekday', '==', weekday).where('status', '==', 'reserved').get();
      res.json(snap.docs.map(d => ({ id: d.id, memberId: d.data().memberId, fullName: d.data().fullName || 'Unknown', reservedAt: d.data().createdAt?.toDate ? d.data().createdAt.toDate().toISOString() : null })));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch reservations' }); }
  });

  router.post('/api/courses/sync-all', verifyAzureToken, async (req, res) => {
    try {
      const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
      const snap = await db.collection('courses').get();
      const courses = [];
      for (const doc of snap.docs) {
        const resSnap = await db.collection('reservations').where('sessionId', '==', doc.id).where('weekday', '==', weekday).where('status', '==', 'reserved').get();
        await doc.ref.update({ reserved: resSnap.size, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
        courses.push({ id: doc.id, ...doc.data(), reserved: resSnap.size });
      }

      // Sync with SQLite courses_cache
      try {
        const lc = require('../localCache');
        if (lc && typeof lc.upsertCourses === 'function') {
          lc.upsertCourses(courses);
        }
      } catch (cErr) {
        console.warn('[COURSES CACHE] sync-all failed:', cErr.message);
      }

      res.json({ ok: true, message: `Synced ${snap.size} courses.` });
    } catch (err) { res.status(500).json({ error: 'Sync failed' }); }
  });

  // ── Coaches ───────────────────────────────────────────────────────────────
  router.get('/api/coaches', verifyAzureToken, async (req, res) => {
    try {
      const gymId = req.query.gymId || (req.assignedGyms.includes('all') ? null : req.assignedGyms[0]);
      let query = db.collection('coaches');
      if (gymId && gymId !== 'all') query = query.where('gymId', '==', gymId);

      const snap = await query.orderBy('createdAt', 'desc').get();
      res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch coaches' }); }
  });

  router.post('/api/coaches', verifyAzureToken, async (req, res) => {
    try {
      const { name, surname, specialty, phone, email, hireDate, bio, photo, gymId } = req.body;
      if (!name || !surname || !specialty || !gymId) return res.status(400).json({ error: 'name, surname, specialty and gymId required' });

      if (!req.hasAccessToGym(gymId)) return res.status(403).json({ error: 'Unauthorized for this gym' });

      const qrToken = crypto.randomBytes(16).toString('hex');
      const docRef = await db.collection('coaches').add({
        name, surname, specialty, phone: phone || null, email: email || null,
        hireDate: hireDate || null, bio: bio || null, photo: photo || null,
        gymId,
        qrToken,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: req.user?.preferred_username || 'Admin'
      });
      const snap = await docRef.get();
      res.json({ id: docRef.id, ...snap.data() });
    } catch (err) { res.status(500).json({ error: 'Failed to create coach' }); }
  });

  router.put('/api/coaches/:id', verifyAzureToken, async (req, res) => {
    try {
      const allowed = ['name', 'surname', 'specialty', 'phone', 'email', 'hireDate', 'bio', 'photo'];
      const update = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, req.body[k]]));
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      const ref = db.collection('coaches').doc(req.params.id);
      await ref.update(update);
      const snap = await ref.get();
      res.json({ id: snap.id, ...snap.data() });
    } catch (err) { res.status(500).json({ error: 'Failed to update coach' }); }
  });

  router.delete('/api/coaches/:id', verifyAzureToken, async (req, res) => {
    try { await db.collection('coaches').doc(req.params.id).delete(); res.json({ ok: true }); }
    catch (err) { res.status(500).json({ error: 'Failed to delete coach' }); }
  });

  router.get('/public/coach-pass/:token', async (req, res) => {
    try {
      const snap = await db.collection('coaches').where('qrToken', '==', req.params.token).limit(1).get();
      if (snap.empty) return res.status(404).json({ error: 'Coach pass not found' });
      const docSnap = snap.docs[0]; const data = docSnap.data();
      await docSnap.ref.update({ qrToken: admin.firestore.FieldValue.delete() });
      await db.collection('access_logs').add({ coachId: docSnap.id, usedAt: admin.firestore.FieldValue.serverTimestamp(), type: 'coach_qr' });
      const firebaseCustomToken = await admin.auth().createCustomToken(`coach_${docSnap.id}`, { role: 'coach' });
      res.json({ ok: true, firebaseCustomToken, coach: { id: docSnap.id, name: data.name, surname: data.surname, specialty: data.specialty } });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
  });

  router.get('/api/coaches/:id/participants', verifyAzureToken, async (req, res) => {
    try {
      const coachDoc = await db.collection('coaches').doc(req.params.id).get();
      if (!coachDoc.exists) return res.status(404).json({ error: 'Coach not found' });
      const { name, surname } = coachDoc.data();
      const coachName = `${name} ${surname}`.trim();
      const [fullSnap, firstSnap] = await Promise.all([db.collection('courses').where('coach', '==', coachName).get(), db.collection('courses').where('coach', '==', name).get()]);
      const courseIds = new Set([...fullSnap.docs.map(d => d.id), ...firstSnap.docs.map(d => d.id)]);
      if (courseIds.size === 0) return res.json([]);
      const idArr = Array.from(courseIds);
      const chunks = []; for (let i = 0; i < idArr.length; i += 30) chunks.push(idArr.slice(i, i + 30));
      const allRes = [];
      for (const chunk of chunks) {
        const s = await db.collection('reservations').where('sessionId', 'in', chunk).where('status', '==', 'reserved').get();
        s.docs.forEach(d => { const r = d.data(); allRes.push({ id: d.id, memberId: r.memberId, fullName: r.fullName || 'Unknown', courseId: r.sessionId, courseName: fullSnap.docs.find(c => c.id === r.sessionId)?.data()?.title || '—', weekday: r.weekday, reservedAt: r.createdAt?.toDate ? r.createdAt.toDate().toISOString() : null }); });
      }
      const seen = new Set();
      res.json(allRes.filter(r => { if (seen.has(r.memberId)) return false; seen.add(r.memberId); return true; }));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch participants' }); }
  });

  // ── GET /api/coaches/private-clients ──────────────────────────────────────
  // Every client whose inscription includes private coaching — grouped by club.
  // Coaching is detected from MULTIPLE signals so we don't miss anyone:
  //   1. the explicit add-on (coachingOption / coachingSessions / coachingPrice), and
  //   2. coaching bundled INTO the subscription itself (subscriptionName contains
  //      "COACHING" — e.g. a 1-an / 6-mois pack with séances included).
  // The full scan is cached 10 min (keyed on nothing) so gym/min changes are free.
  let _pcCache = { ts: 0, rows: null };
  router.get('/api/coaches/private-clients', verifyAzureToken, async (req, res) => {
    try {
      const minSessions = parseInt(req.query.min) || 10;
      const gymScope = (req.query.gymId || 'all').toLowerCase();
      const GYM_NAMES = { dokarat: 'Fès Dokkarat', marjane: 'Fès Saïss', casa1: 'Casa Anfa', casa2: 'Casa Lady' };
      const canSee = (g) => req.isAdmin || (typeof req.hasAccessToGym === 'function' ? req.hasAccessToGym(g) : true);

      // Build/refresh the cross-club coaching roster (all clubs, unfiltered).
      if (!_pcCache.rows || Date.now() - _pcCache.ts > 10 * 60 * 1000) {
        const snap = await db.collection('pending_members').get();
        const rows = [];
        snap.docs.forEach(d => {
          const m = d.data();
          if (m.status === 'deleted' || m.deleted || m.isDeleted) return;

          const subName = (m.subscriptionName || '').toString();
          const cs = (m.coachingSessions || '').toString().trim();
          const price = Number(m.coachingPrice) || 0;
          const hasCoaching = m.coachingOption === true || cs !== '' || price > 0 || /coaching/i.test(subName);
          if (!hasCoaching) return;

          // Séance count: prefer the coaching formula, else parse it out of the subscription name.
          let sessions = 0;
          const fromCs = cs.match(/(\d+)\s*S[EÉ]ANCE/i) || (cs ? cs.match(/(\d+)/) : null);
          const fromSub = subName.match(/coaching[^0-9]{0,20}(\d+)/i) || (/coaching/i.test(subName) ? subName.match(/(\d+)\s*S[EÉ]ANCE/i) : null);
          const num = fromCs || fromSub;
          if (num) sessions = parseInt(num[1]);
          const included = sessions === 0; // coaching present but no explicit count → bundled in the plan

          const createdAt = m.createdAt?.toDate ? m.createdAt.toDate().toISOString()
            : (m.createdAt?._seconds ? new Date(m.createdAt._seconds * 1000).toISOString() : null);

          rows.push({
            id: d.id,
            gymId: (m.gymId || 'unknown').toLowerCase(),
            fullName: `${m.prenom || ''} ${m.nom || ''}`.trim() || m.fullName || 'Inconnu',
            phone: m.telephone || m.phone || '',
            formula: cs || (/(coaching[^,;•\n]*)/i.exec(subName)?.[1]?.trim()) || 'Coaching inclus',
            sessions,
            included,
            source: cs || price > 0 || m.coachingOption === true ? 'addon' : 'subscription',
            price,
            subscriptionName: subName,
            contractNumber: m.contractNumber || null,
            commercial: m.commercial || null,
            status: m.status || null,
            createdAt,
          });
        });
        _pcCache = { ts: Date.now(), rows };
      }

      const order = ['dokarat', 'marjane', 'casa1', 'casa2'];

      // Rows this user is allowed to see (manager access + selected club).
      const accessible = _pcCache.rows.filter(r => canSee(r.gymId) && (gymScope === 'all' || r.gymId === gymScope));

      // ── STATS: count ALL coaching per club (both add-on AND bundled-in-subscription),
      //    independent of the séance threshold. This is the "compter tout" view. ──
      const statMap = {};
      accessible.forEach(r => {
        const s = statMap[r.gymId] = statMap[r.gymId] || { gymId: r.gymId, gymName: GYM_NAMES[r.gymId] || r.gymId, count: 0, sessions: 0, revenue: 0, addon: 0, included: 0 };
        s.count++;
        s.sessions += r.sessions;
        s.revenue += r.price || 0;
        if (r.included) s.included++; else s.addon++;
      });
      const byClub = [];
      order.forEach(g => { if (statMap[g]) byClub.push(statMap[g]); });
      Object.keys(statMap).forEach(g => { if (!order.includes(g)) byClub.push(statMap[g]); });
      const totals = byClub.reduce((t, s) => ({
        count: t.count + s.count, sessions: t.sessions + s.sessions,
        revenue: t.revenue + s.revenue, addon: t.addon + s.addon, included: t.included + s.included,
      }), { count: 0, sessions: 0, revenue: 0, addon: 0, included: 0 });

      // ── DETAILED LIST: respects the séance threshold. Bundled/unknown-count coaching
      //    only appears at the base level (10+ / Tous), not at 20+/50+/100+. ──
      const clubs = {};
      accessible.forEach(r => {
        if (r.included) { if (minSessions > 10) return; }
        else if (r.sessions < minSessions) return;
        (clubs[r.gymId] = clubs[r.gymId] || []).push(r);
      });
      Object.values(clubs).forEach(arr => arr.sort((a, b) => b.sessions - a.sessions || (b.createdAt || '').localeCompare(a.createdAt || '')));
      const result = [];
      const build = g => ({ gymId: g, gymName: GYM_NAMES[g] || g, count: clubs[g].length, sessionsTotal: clubs[g].reduce((s, r) => s + r.sessions, 0), clients: clubs[g] });
      order.forEach(g => { if (clubs[g]?.length) result.push(build(g)); });
      Object.keys(clubs).forEach(g => { if (!order.includes(g)) result.push(build(g)); });

      res.json({ total: result.reduce((s, c) => s + c.count, 0), minSessions, stats: { byClub, totals }, clubs: result });
    } catch (err) {
      console.error('[private-clients]', err.message);
      res.status(500).json({ error: 'Failed to fetch private coaching clients' });
    }
  });

  router.get('/api/reservations-global', verifyAzureToken, async (req, res) => {
    try {
      const snap = await db.collection('reservations').orderBy('createdAt', 'desc').limit(200).get();
      res.json(snap.docs.map(doc => {
        const d = doc.data();
        let createdAt = null;
        if (d.createdAt?.toDate) createdAt = d.createdAt.toDate().toISOString();
        else if (d.createdAt?._seconds) createdAt = new Date(d.createdAt._seconds * 1000).toISOString();
        else if (doc.createTime) createdAt = doc.createTime.toDate().toISOString();
        return { id: doc.id, memberId: d.memberId, fullName: d.fullName || 'Unknown', courseTitle: d.courseTitle || '—', coachName: d.coach || '—', dayName: d.dayName || '—', startTime: d.start_time || '—', endTime: d.end_time || '—', weekday: d.weekday, status: d.status, createdAt };
      }));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch global reservations' }); }
  });

  // ── Coach Bilans ──────────────────────────────────────────────────────────
  router.get('/api/coach-reservations', verifyAzureToken, async (req, res) => {
    try {
      const { status } = req.query;
      let query = db.collection('coach_reservations');
      if (status && status !== 'both') query = query.where('status', '==', status);
      const snap = await query.get();
      const data = snap.docs.map(doc => {
        const d = doc.data();
        let resolvedDate = null;
        if (d.createdAt?.toDate) resolvedDate = d.createdAt.toDate().toISOString();
        else if (d.createdAt?._seconds) resolvedDate = new Date(d.createdAt._seconds * 1000).toISOString();
        else if (doc.createTime) resolvedDate = doc.createTime.toDate().toISOString();
        return { id: doc.id, ...d, createdAt: resolvedDate };
      }).sort((a, b) => (b.createdAt ? new Date(b.createdAt).getTime() : 0) - (a.createdAt ? new Date(a.createdAt).getTime() : 0));
      res.json(data);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch bilans' }); }
  });

  router.put('/api/coach-reservations/:id', verifyAzureToken, async (req, res) => {
    try {
      const { status, coachNotes, coachId, coachName } = req.body;
      const ref = db.collection('coach_reservations').doc(req.params.id);
      const update = {};
      if (status) update.status = status;
      if (coachNotes !== undefined) update.coachNotes = coachNotes;
      if (coachId !== undefined) update.coachId = coachId;
      if (coachName !== undefined) update.coachName = coachName;
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      await ref.update(update);
      const snap = await ref.get();
      res.json({ id: snap.id, ...snap.data() });
    } catch (err) { res.status(500).json({ error: 'Failed to update bilan' }); }
  });

  // ── Coach Ratings & AI Programs (New) ──────────────────────────────────────

  // 1. Submit Coach Rating (Used by mobile app/PWA and dashboard)
  router.post('/api/coach-ratings', async (req, res) => {
    try {
      const { reservationId, coachId, coachName, rating, comment, memberId, memberName, courseTitle } = req.body;
      if (!coachId || !rating || !memberId) {
        return res.status(400).json({ error: 'coachId, rating and memberId are required' });
      }

      const ratingData = {
        reservationId: reservationId || '',
        coachId,
        coachName: coachName || '',
        rating: Number(rating),
        comment: comment || '',
        memberId,
        memberName: memberName || '',
        courseTitle: courseTitle || '',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      const docRef = await db.collection('coach_ratings').add(ratingData);

      if (reservationId) {
        try {
          await db.collection('reservations').doc(reservationId).update({
            status: 'completed_rated',
            ratedAt: admin.firestore.FieldValue.serverTimestamp()
          });
        } catch (err) {
          console.warn(`[COACH RATINGS] Failed to update reservation ${reservationId}:`, err.message);
        }
      }

      res.json({ ok: true, id: docRef.id });
    } catch (err) {
      console.error('Failed to submit coach rating:', err);
      res.status(500).json({ error: 'Failed to submit coach rating' });
    }
  });

  // 2. Fetch Average Rating (Used by mobile app and dashboard)
  router.get('/api/coaches/average-rating/:coachName', async (req, res) => {
    try {
      const { coachName } = req.params;
      const snap = await db.collection('coach_ratings').where('coachName', '==', coachName).get();
      if (snap.empty) {
        return res.json({ ok: true, averageRating: 0, totalRatings: 0 });
      }
      let sum = 0;
      snap.docs.forEach(doc => {
        sum += (Number(doc.data().rating) || 0);
      });
      const avg = Number((sum / snap.size).toFixed(1));
      res.json({
        ok: true,
        averageRating: avg,
        totalRatings: snap.size
      });
    } catch (err) {
      console.error('Failed to fetch coach average rating:', err);
      res.status(500).json({ error: 'Failed to fetch average rating' });
    }
  });

  // 3. Fetch All Coach Ratings (Used by dashboard)
  router.get('/api/coaches/ratings', verifyAzureToken, async (req, res) => {
    try {
      const snap = await db.collection('coach_ratings').orderBy('createdAt', 'desc').limit(1000).get();
      res.json(snap.docs.map(doc => {
        const d = doc.data();
        let createdAt = null;
        if (d.createdAt?.toDate) createdAt = d.createdAt.toDate().toISOString();
        else if (d.createdAt?._seconds) createdAt = new Date(d.createdAt._seconds * 1000).toISOString();
        return { id: doc.id, ...d, createdAt };
      }));
    } catch (err) {
      console.error('Failed to fetch coach ratings:', err);
      res.status(500).json({ error: 'Failed to fetch coach ratings' });
    }
  });

  // 4. Fetch AI Program Summary for All Active Members (Used by dashboard)
  router.get('/api/coaches/ai-programs-summary', verifyAzureToken, async (req, res) => {
    try {
      const snap = await db.collection('coach_reservations')
        .where('aiGenerated', '==', true)
        .get();

      const memberMap = new Map();

      snap.docs.forEach(doc => {
        const d = doc.data();
        const memberId = d.memberId;
        if (!memberId) return;

        let createdAt = null;
        if (d.createdAt?.toDate) createdAt = d.createdAt.toDate().toISOString();
        else if (d.createdAt?._seconds) createdAt = new Date(d.createdAt._seconds * 1000).toISOString();
        else if (doc.createTime) createdAt = doc.createTime.toDate().toISOString();

        // Calculate workouts completed
        let totalWorkoutsCompleted = 0;
        if (d.dailyProgress) {
          Object.values(d.dailyProgress).forEach(log => {
            if (log && log.workoutCompleted) {
              totalWorkoutsCompleted++;
            }
          });
        }

        const memberData = {
          memberId,
          memberName: d.memberName || 'Unknown',
          goal: d.goal || d.aiProfile?.goal || 'General Fitness',
          level: d.level || d.aiProfile?.level || 'beginner',
          daysPerWeek: d.daysPerWeek || d.aiProfile?.daysPerWeek || 3,
          equipment: d.equipment || d.aiProfile?.equipment || 'none',
          points: d.points || 0,
          coachingLevel: d.coachingLevel || d.level || 1,
          totalWorkoutsCompleted,
          latestProgramDate: createdAt,
          rawCreatedAt: createdAt ? new Date(createdAt).getTime() : 0
        };

        const existing = memberMap.get(memberId);
        if (!existing || memberData.rawCreatedAt > existing.rawCreatedAt) {
          memberMap.set(memberId, memberData);
        }
      });

      const members = Array.from(memberMap.values()).sort((a, b) => b.rawCreatedAt - a.rawCreatedAt);
      members.forEach(m => delete m.rawCreatedAt);

      res.json({ ok: true, members });
    } catch (err) {
      console.error('Failed to fetch AI programs summary:', err);
      res.status(500).json({ error: 'Failed to fetch AI programs summary' });
    }
  });

  // 5. Fetch AI Programs & Progress for a Specific Member (Used by dashboard)
  router.get('/api/coaches/member-ai-programs/:memberId', verifyAzureToken, async (req, res) => {
    try {
      const { memberId } = req.params;
      const snap = await db.collection('coach_reservations')
        .where('memberId', '==', memberId)
        .where('aiGenerated', '==', true)
        .get();

      const programs = snap.docs.map(doc => {
        const d = doc.data();
        let createdAt = null;
        if (d.createdAt?.toDate) createdAt = d.createdAt.toDate().toISOString();
        else if (d.createdAt?._seconds) createdAt = new Date(d.createdAt._seconds * 1000).toISOString();
        else if (doc.createTime) createdAt = doc.createTime.toDate().toISOString();

        return {
          id: doc.id,
          ...d,
          createdAt
        };
      });

      programs.sort((a, b) => {
        const timeA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const timeB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return timeB - timeA;
      });

      res.json({ ok: true, programs });
    } catch (err) {
      console.error(`Failed to fetch AI programs for member ${memberId}:`, err);
      res.status(500).json({ error: 'Failed to fetch member AI programs' });
    }
  });

  // 6. Fetch Member Audit Logs (Used by dashboard)
  router.get('/api/coaches/member-audit-logs/:memberId', verifyAzureToken, async (req, res) => {
    try {
      const { memberId } = req.params;
      const limit = Number(req.query.limit) || 50;

      // 1. Fetch push notifications sent to this member from Firestore push_notifications_history
      const notifSnap = await db.collection('push_notifications_history')
        .orderBy('timestamp', 'desc')
        .limit(200)
        .get();

      const memberNotifs = [];
      notifSnap.docs.forEach(doc => {
        const data = doc.data();
        const hasMember = (data.recipients || []).some(r => r.id === memberId);
        if (hasMember) {
          memberNotifs.push({
            id: doc.id,
            action: 'notification_sent',
            memberId,
            title: data.title || '',
            timestamp: data.timestamp
          });
        }
      });

      // 2. Fetch NFC / Access Swipes for this member
      const accessSnap = await db.collection('access_logs')
        .where('memberId', '==', memberId)
        .limit(100)
        .get();

      const memberAccess = accessSnap.docs.map(doc => {
        const data = doc.data();
        let timestamp = null;
        if (data.usedAt?.toDate) timestamp = data.usedAt.toDate().toISOString();
        else if (data.usedAt?._seconds) timestamp = new Date(data.usedAt._seconds * 1000).toISOString();
        return {
          id: doc.id,
          action: data.type === 'nfc' ? 'nfc_access_granted' : 'qr_access_granted',
          memberId,
          timestamp
        };
      });

      // 3. Fetch AI Coach Interactions / program generations from coach_reservations
      const aiSnap = await db.collection('coach_reservations')
        .where('memberId', '==', memberId)
        .where('aiGenerated', '==', true)
        .get();

      const memberAi = aiSnap.docs.map(doc => {
        const data = doc.data();
        let timestamp = null;
        if (data.createdAt?.toDate) timestamp = data.createdAt.toDate().toISOString();
        else if (data.createdAt?._seconds) timestamp = new Date(data.createdAt._seconds * 1000).toISOString();
        return {
          id: doc.id,
          action: 'ai_program_generated',
          memberId,
          title: `Programme IA (${data.goal || 'Remise en forme'})`,
          timestamp
        };
      });

      // Combine, sort descending, and limit
      const allLogs = [...memberNotifs, ...memberAccess, ...memberAi];
      allLogs.sort((a, b) => {
        const tA = a.timestamp ? new Date(a.timestamp).getTime() : 0;
        const tB = b.timestamp ? new Date(b.timestamp).getTime() : 0;
        return tB - tA;
      });

      res.json({ ok: true, logs: allLogs.slice(0, limit) });
    } catch (err) {
      console.error(`Failed to fetch audit logs for member ${req.params.memberId}:`, err);
      res.status(500).json({ error: 'Failed to fetch member audit logs' });
    }
  });

  return router;
};
