
# rebuild_analytics_tail.ps1
# Cuts analytics.js at the corruption point and appends correct route code

$tail = @'
  // ── INCIDENTS (SQLite-backed, Firestore-write-through) ──────────────────────
  // Cache TTL: 10 minutes — avoids Firestore reads on every dashboard refresh
  const INCIDENTS_TTL_MS = 10 * 60 * 1000;
  let incidentsCachedAt = 0;

  async function syncIncidentsFromFirestore() {
    const now = Date.now();
    if (now - incidentsCachedAt < INCIDENTS_TTL_MS) return;
    try {
      const snap = await db.collection('incidents').orderBy('createdAt', 'desc').limit(200).get();
      const rows = snap.docs.map(d => {
        const data = d.data();
        return {
          id: d.id,
          gymId: data.gymId || '',
          gymName: data.gymName || '',
          title: data.title || '',
          cause: data.cause || '',
          explanation: data.explanation || '',
          emergency: data.emergency || 'Low',
          status: data.status || 'Pending',
          reporter: data.reporter || '',
          date: data.date || '',
          createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : new Date().toISOString(),
        };
      });
      lc.upsertIncidents(rows);
      incidentsCachedAt = now;
      console.log(`[INCIDENTS] Synced ${rows.length} incidents to SQLite`);
    } catch (err) {
      console.error('[INCIDENTS] Firestore sync failed, serving stale cache:', err.message);
    }
  }

  // GET /api/incidents
  router.get('/api/incidents', verifyAzureToken, async (req, res) => {
    try {
      await syncIncidentsFromFirestore();
      const gymId = req.query.gymId || 'all';
      const rows = lc.getIncidents(gymId);
      const out = rows.map(r => ({
        id: r.id, gymId: r.gym_id, gymName: r.gym_name,
        title: r.title, cause: r.cause, explanation: r.explanation,
        emergency: r.emergency, status: r.status,
        reporter: r.reporter, date: r.date, createdAt: r.created_at,
      }));
      res.json(out);
    } catch (err) {
      console.error('[INCIDENTS GET] error:', err);
      res.status(500).json({ error: 'Failed to fetch incidents' });
    }
  });

  // POST /api/incidents
  router.post('/api/incidents', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, gymName, title, cause, explanation, emergency, reporter, date } = req.body;
      const docRef = await db.collection('incidents').add({
        gymId, gymName, title, cause, explanation, emergency,
        reporter, date, status: 'Pending',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      const now = new Date().toISOString();
      lc.upsertIncidents([{ id: docRef.id, gymId, gymName, title, cause, explanation, emergency, reporter, date, status: 'Pending', createdAt: now }]);
      incidentsCachedAt = 0;
      res.json({ id: docRef.id, gymId, gymName, title, cause, explanation, emergency, reporter, date, status: 'Pending', createdAt: now });
    } catch (err) {
      console.error('[INCIDENTS POST] error:', err);
      res.status(500).json({ error: 'Failed to create incident' });
    }
  });

  // PATCH /api/incidents/:id/resolve
  router.patch('/api/incidents/:id/resolve', verifyAzureToken, async (req, res) => {
    try {
      lc.resolveIncidentCache(req.params.id);
      db.collection('incidents').doc(req.params.id).update({
        status: 'Resolved', updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }).catch(err => console.error('[INCIDENTS RESOLVE Firestore]', err.message));
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to resolve incident' });
    }
  });

  // ── KIDS COURSES (SQLite read, Firestore write-through on mutations) ──────────
  // READ  → always SQLite (zero Firestore reads)
  // WRITE → SQLite immediately + Firestore fire-and-forget (backup/sync)
  // STARTUP RECOVERY → if SQLite empty, pull once from Firestore

  async function syncKidsFromFirestore(gymId) {
    try {
      const snap = await db.collection('kids_courses').where('gymId', '==', gymId).get();
      if (snap.empty) return;
      snap.docs.forEach(d => {
        const data = d.data();
        lc.upsertKidsCourse({
          id: d.id,
          gymId: data.gymId || gymId,
          groupId: data.groupId || '',
          groupName: data.groupName || '',
          day: data.day || '',
          timeStart: data.timeStart || '',
          timeEnd: data.timeEnd || '',
          activity: data.activity || '',
          ages: data.ages || '',
        });
      });
      console.log(`[KIDS] Recovered ${snap.size} sessions from Firestore → SQLite`);
    } catch (err) {
      console.error('[KIDS] Firestore recovery failed:', err.message);
    }
  }

  function kidsRow(r) {
    return {
      id: r.id, gymId: r.gym_id, groupId: r.group_id, groupName: r.group_name,
      day: r.day, timeStart: r.time_start, timeEnd: r.time_end,
      activity: r.activity, ages: r.ages, updatedAt: r.updated_at,
    };
  }

  // GET /public/kids-courses — no auth (mobile app)
  router.get('/public/kids-courses', async (req, res) => {
    try {
      const gymId = req.query.gym || 'dokarat';
      let rows = lc.getKidsCourses(gymId);
      if (rows.length === 0) { await syncKidsFromFirestore(gymId); rows = lc.getKidsCourses(gymId); }
      res.json(rows.map(kidsRow));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch kids courses' }); }
  });

  // GET /api/kids-courses — authenticated dashboard
  router.get('/api/kids-courses', verifyAzureToken, async (req, res) => {
    try {
      const gymId = req.query.gym || 'dokarat';
      let rows = lc.getKidsCourses(gymId);
      if (rows.length === 0) { await syncKidsFromFirestore(gymId); rows = lc.getKidsCourses(gymId); }
      res.json(rows.map(kidsRow));
    } catch (err) { res.status(500).json({ error: 'Failed to fetch kids courses' }); }
  });

  // POST /api/kids-courses — create + write-through to Firestore
  router.post('/api/kids-courses', verifyAzureToken, async (req, res) => {
    try {
      const { gymId, groupId, groupName, day, timeStart, timeEnd, activity, ages } = req.body;
      if (!groupId || !day || !timeStart || !timeEnd || !activity || !ages) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
      const id = lc.upsertKidsCourse({ gymId: gymId || 'dokarat', groupId, groupName, day, timeStart, timeEnd, activity, ages });
      // Fire-and-forget Firestore sync
      db.collection('kids_courses').doc(id).set({
        gymId: gymId || 'dokarat', groupId, groupName, day, timeStart, timeEnd, activity, ages,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(e => console.error('[KIDS POST Firestore]', e.message));
      res.json({ id, gymId: gymId || 'dokarat', groupId, groupName, day, timeStart, timeEnd, activity, ages });
    } catch (err) { res.status(500).json({ error: 'Failed to create kids course' }); }
  });

  // PUT /api/kids-courses/:id — update + write-through to Firestore
  router.put('/api/kids-courses/:id', verifyAzureToken, async (req, res) => {
    try {
      const { groupId, groupName, day, timeStart, timeEnd, activity, ages } = req.body;
      lc.updateKidsCourse(req.params.id, {
        group_id: groupId, group_name: groupName, day,
        time_start: timeStart, time_end: timeEnd, activity, ages,
      });
      // Fire-and-forget Firestore sync
      db.collection('kids_courses').doc(req.params.id).update({
        groupId, groupName, day, timeStart, timeEnd, activity, ages,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(e => console.error('[KIDS PUT Firestore]', e.message));
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to update kids course' }); }
  });

  // DELETE /api/kids-courses/:id — delete from SQLite + Firestore
  router.delete('/api/kids-courses/:id', verifyAzureToken, async (req, res) => {
    try {
      lc.deleteKidsCourse(req.params.id);
      db.collection('kids_courses').doc(req.params.id).delete()
        .catch(e => console.error('[KIDS DELETE Firestore]', e.message));
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: 'Failed to delete kids course' }); }
  });

  // POST /api/kids-courses/seed — reset to official schedule (idempotent)
  router.post('/api/kids-courses/seed', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const defaults = [
        { groupId:'A', groupName:'Les MEGAfit Dynamiques',       day:'Mercredi', timeStart:'14:30', timeEnd:'15:30', activity:'Natation', ages:'5ans-9ans' },
        { groupId:'A', groupName:'Les MEGAfit Dynamiques',       day:'Samedi',   timeStart:'10:00', timeEnd:'11:00', activity:'Funfit',   ages:'5ans-8ans' },
        { groupId:'A', groupName:'Les MEGAfit Dynamiques',       day:'Dimanche', timeStart:'10:00', timeEnd:'11:00', activity:'Natation', ages:'5ans-9ans' },
        { groupId:'B', groupName:'Les MEGAfit Junior-Energie',   day:'Mercredi', timeStart:'15:30', timeEnd:'16:30', activity:'Natation', ages:'10ans-14ans' },
        { groupId:'B', groupName:'Les MEGAfit Junior-Energie',   day:'Samedi',   timeStart:'11:00', timeEnd:'12:00', activity:'Funfit',   ages:'9ans-14ans' },
        { groupId:'B', groupName:'Les MEGAfit Junior-Energie',   day:'Dimanche', timeStart:'11:00', timeEnd:'12:00', activity:'Natation', ages:'10ans-14ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Vendredi', timeStart:'15:00', timeEnd:'16:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Samedi',   timeStart:'10:00', timeEnd:'11:00', activity:'Funfit',   ages:'5ans-8ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Samedi',   timeStart:'11:00', timeEnd:'12:00', activity:'Funfit',   ages:'9ans-14ans' },
        { groupId:'C', groupName:'Les MEGAfit Aqua Nageurs',     day:'Dimanche', timeStart:'12:00', timeEnd:'13:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'D', groupName:'Les MEGAfit Futurs Champions', day:'Samedi',   timeStart:'14:00', timeEnd:'15:00', activity:'Funfit',   ages:'5ans-14ans' },
        { groupId:'D', groupName:'Les MEGAfit Futurs Champions', day:'Samedi',   timeStart:'15:00', timeEnd:'16:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'D', groupName:'Les MEGAfit Futurs Champions', day:'Dimanche', timeStart:'12:00', timeEnd:'13:00', activity:'Natation', ages:'5ans-14ans' },
        { groupId:'E', groupName:'Les MEGAfit Tout-Petits',      day:'Mercredi', timeStart:'14:30', timeEnd:'15:30', activity:'Natation', ages:'3ans-4ans'  },
        { groupId:'E', groupName:'Les MEGAfit Tout-Petits',      day:'Dimanche', timeStart:'10:00', timeEnd:'11:00', activity:'Natation', ages:'3ans-4ans'  },
      ];
      defaults.forEach(d => lc.upsertKidsCourse({ ...d, gymId: 'dokarat' }));
      // Sync seeded data to Firestore in background
      Promise.all(defaults.map(d => {
        const id = lc.getKidsCourses('dokarat').find(r =>
          r.group_id === d.groupId && r.day === d.day && r.time_start === d.timeStart
        )?.id;
        if (!id) return;
        return db.collection('kids_courses').doc(id).set({
          ...d, gymId: 'dokarat',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      })).catch(e => console.error('[KIDS SEED Firestore]', e.message));
      res.json({ ok: true, seeded: defaults.length });
    } catch (err) { res.status(500).json({ error: 'Seed failed' }); }
  });

  return router;
};
'@

$raw = Get-Content "routes\analytics.js" -Raw -Encoding UTF8
$splitPoint = $raw.IndexOf("  // ``u2500``u2500 INCIDENTS")
# PowerShell backtick is escape char — need to find the actual unicode character
$splitPoint = $raw.IndexOf("  // " + [char]0x2500 + [char]0x2500 + " INCIDENTS")
if ($splitPoint -lt 0) {
    # Try finding the escaped version of the incidents comment
    $splitPoint = $raw.IndexOf("  // \u2500\u2500 INCIDENTS")
}
Write-Host "Found corruption at: $splitPoint"
$good = $raw.Substring(0, $splitPoint)
$newContent = $good + "`r`n" + $tail
[System.IO.File]::WriteAllText("routes\analytics.js", $newContent, [System.Text.Encoding]::UTF8)
Write-Host "File rebuilt: $($newContent.Length) chars"
