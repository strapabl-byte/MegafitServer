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
      const gymId = req.query.gymId || (req.assignedGyms.includes('all') ? null : req.assignedGyms[0]);
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
      res.json({ id: docRef.id, ...snap.data(), reserved: 0 });
    } catch (err) { res.status(500).json({ error: 'Failed to create course' }); }
  });

  router.put('/api/courses/:id', verifyAzureToken, async (req, res) => {
    try {
      const allowed = ['title', 'coach', 'days', 'time', 'capacity'];
      const update  = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, k === 'capacity' ? Number(req.body[k]) : req.body[k]]));
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      const ref = db.collection('courses').doc(req.params.id);
      await ref.update(update);
      const snap = await ref.get();
      res.json({ id: snap.id, ...snap.data() });
    } catch (err) { res.status(500).json({ error: 'Failed to update course' }); }
  });

  router.delete('/api/courses/:id', verifyAzureToken, async (req, res) => {
    try { await db.collection('courses').doc(req.params.id).delete(); res.json({ ok: true }); }
    catch (err) { res.status(500).json({ error: 'Failed to delete course' }); }
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
      for (const doc of snap.docs) {
        const resSnap = await db.collection('reservations').where('sessionId', '==', doc.id).where('weekday', '==', weekday).where('status', '==', 'reserved').get();
        await doc.ref.update({ reserved: resSnap.size, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
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
      const docRef  = await db.collection('coaches').add({ 
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
      const update  = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, req.body[k]]));
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
      const { status, coachNotes } = req.body;
      const ref = db.collection('coach_reservations').doc(req.params.id);
      const update = {};
      if (status) update.status = status;
      if (coachNotes !== undefined) update.coachNotes = coachNotes;
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      await ref.update(update);
      const snap = await ref.get();
      res.json({ id: snap.id, ...snap.data() });
    } catch (err) { res.status(500).json({ error: 'Failed to update bilan' }); }
  });

  return router;
};
