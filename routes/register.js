'use strict';
// routes/register.js — Daily Register (Registre Journalier) + Calendar

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function registerRouter({ db, admin, lc, apiCache, isQuotaExceeded, getCachedOrFetch, invalidateCache }) {
  const router = Router();

  // ── GET /api/register ─────────────────────────────────────────────────────
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.query;
      if (!date) return res.status(400).json({ error: 'date required (YYYY-MM-DD)' });

      const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : [gymId];
      let entries = [];
      let decaissements = [];

      // 1️⃣ Try SQLite cache first
      const cached = lc.getRegister(gymId, date);
      const cachedDec = lc.getDecaissements(gymId, date);
      
      // 🛡️ CORRUPTION DETECTION: If any entry has lost its name but has other data (prix, tel, cin), 
      // it's a victim of the partial-update bug. Trigger "Self-Heal" re-sync.
      const isCorrupt = cached && cached.length > 0 && cached.some(e => {
        const hasData = (Number(e.prix) > 0 || Number(e.tpe) > 0 || Number(e.espece) > 0 || (e.tel && e.tel.length > 4) || (e.cin && e.cin.length > 2));
        const noName = !e.nom || e.nom.trim() === '';
        return hasData && noName;
      });

      if (cached && cached.length > 0 && !isCorrupt) {
        console.log(`⚡ [SQLITE HIT] ${cached.length} register entries for ${date}`);
        entries = cached.map(e => ({ ...e, createdAt: e.created_at }));
        decaissements = cachedDec.map(d => ({ ...d, createdAt: d.created_at }));
      } else {
        if (isCorrupt) console.warn(`🩹 [SELF-HEAL] Detected missing names in SQLite for ${date}. Re-syncing from Firestore...`);
        
        // 2️⃣ Firestore fallback (or re-sync)
        if (isQuotaExceeded()) return res.status(429).json({ error: 'Quota exceeded. No local cache for this date.', quotaExceeded: true, entries: [] });
        console.log(`🌐 [SQLITE MISS/REPAIR] Fetching register from Firestore for ${date}...`);
        await Promise.all(gymIds.map(async (gid) => {
          const snap = await db.collection('megafit_daily_register').doc(`${gid}_${date}`).collection('entries').orderBy('createdAt', 'asc').get();
          const fetched = snap.docs.map(d => ({ id: d.id, gymId: gid, ...d.data() }));
          entries = entries.concat(fetched);
          if (fetched.length > 0) lc.upsertRegister(gid, date, fetched);

          const decSnap = await db.collection('megafit_daily_register').doc(`${gid}_${date}`).collection('decaissements').orderBy('createdAt', 'asc').get();
          const fetchedDec = decSnap.docs.map(d => ({ id: d.id, gymId: gid, ...d.data() }));
          decaissements = decaissements.concat(fetchedDec);
          if (fetchedDec.length > 0) lc.upsertDecaissements(gid, date, fetchedDec);
        }));
      }

      entries.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime() || 0);

      const totals = entries.reduce((acc, e) => ({
        tpe:      acc.tpe      + (Number(e.tpe)      || 0),
        espece:   acc.espece   + (Number(e.espece)   || 0),
        virement: acc.virement + (Number(e.virement) || 0),
        cheque:   acc.cheque   + (Number(e.cheque)   || 0),
      }), { tpe: 0, espece: 0, virement: 0, cheque: 0 });
      totals.ca = totals.tpe + totals.espece + totals.virement + totals.cheque;

      const byCommercial = {};
      entries.forEach(e => {
        const name = (e.commercial || '').trim().toUpperCase();
        if (!name) return;
        if (!byCommercial[name]) byCommercial[name] = { tpe: 0, espece: 0, virement: 0, cheque: 0, total: 0 };
        byCommercial[name].tpe      += Number(e.tpe)      || 0;
        byCommercial[name].espece   += Number(e.espece)   || 0;
        byCommercial[name].virement += Number(e.virement) || 0;
        byCommercial[name].cheque   += Number(e.cheque)   || 0;
        byCommercial[name].total    += (Number(e.tpe) || 0) + (Number(e.espece) || 0) + (Number(e.virement) || 0) + (Number(e.cheque) || 0);
      });

      res.json({ ok: true, date, gymId, entries, decaissements, totals, byCommercial });
    } catch (err) {
      console.error('GET /api/register error:', err);
      res.status(500).json({ error: 'Failed to fetch register' });
    }
  });

  // ── POST /api/register/entry ──────────────────────────────────────────────
  router.post('/entry', verifyAzureToken, async (req, res) => {
    try {
      const { date, gymId = 'dokarat', ...entry } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });
      const docId = `${gymId}_${date}`;
      const ref = await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
        ...entry, location: gymId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: req.user?.preferred_username || 'system',
      });
      await db.collection('megafit_daily_register').doc(docId).set({ gymId, date, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      
      const newDoc = await ref.get();
      // ✅ Update the local SQLite cache directly so the new row appears immediately and survives refresh
      lc.upsertRegister(gymId, date, [{ id: ref.id, ...newDoc.data() }]);
      
      invalidateCache(apiCache.calendar, `${gymId}_${new Date(date).getFullYear()}`);
      res.json({ ok: true, id: ref.id });
    } catch (err) {
      console.error('POST /api/register/entry error:', err);
      res.status(500).json({ error: 'Failed to save entry' });
    }
  });

  // ── PUT /api/register/entry/:id ───────────────────────────────────────────
  router.put('/entry/:id', verifyAzureToken, async (req, res) => {
    try {
      const { date, gymId = 'dokarat', ...entry } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });

      const entryId = req.params.id;
      
      // 1️⃣ Fetch existing to prevent partial wipe
      const existing = lc.getRegister(gymId, date).find(e => e.id === entryId);
      const merged = existing ? { ...existing, ...entry } : { id: entryId, ...entry };

      // ✅ Always update SQLite first
      lc.upsertRegister(gymId, date, [merged]);

      // ✅ Then try to sync to Firestore (best effort — won't crash if doc doesn't exist)
      try {
        const docRef = db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('entries').doc(entryId);
        const snap = await docRef.get();
        if (snap.exists) {
          await docRef.update({ ...entry, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
        } else {
          // Document doesn't exist in Firestore (manually seeded) — create it
          await docRef.set({ ...entry, gymId, date, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        }
      } catch (fsErr) {
        console.warn(`⚠️ [REGISTER PUT] Firestore sync failed for ${entryId} — SQLite updated successfully:`, fsErr.message);
      }

      invalidateCache(apiCache.calendar, `${gymId}_${new Date(date).getFullYear()}`);
      res.json({ ok: true });
    } catch (err) {
      console.error('PUT /api/register/entry error:', err);
      res.status(500).json({ error: 'Failed to update entry' });
    }
  });

  // ── DELETE /api/register/entry/:id ───────────────────────────────────────
  router.delete('/entry/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.query;
      if (!date) return res.status(400).json({ error: 'date required' });
      await db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('entries').doc(req.params.id).delete();
      // ✅ Also remove from SQLite cache so it doesn't reappear on refresh
      lc.deleteRegisterEntry(gymId, date, req.params.id);
      invalidateCache(apiCache.calendar, `${gymId}_${new Date(date).getFullYear()}`);
      res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /api/register/entry error:', err);
      res.status(500).json({ error: 'Failed to delete entry' });
    }
  });

  // ── GET /api/register/calendar ────────────────────────────────────────────
  router.get('/calendar', verifyAzureToken, async (req, res) => {
    try {
      const { year = new Date().getFullYear(), gymId = 'dokarat' } = req.query;
      const cacheKey = `${gymId}_${year}`;

      const result = await getCachedOrFetch(apiCache.calendar, cacheKey, 10 * 60 * 1000, async () => {
        const gymIds = gymId === 'all' ? ['marjane', 'dokarat', 'casa1', 'casa2'] : [gymId];
        const calendarData = {}, resteData = {};
        const yearStr = String(year);

        // ── Build date range for the year ──
        const startDate = new Date(`${yearStr}-01-01`);
        const endDate   = new Date(`${yearStr}-12-31`);

        for (const gid of gymIds) {
          const cursor = new Date(startDate);
          while (cursor <= endDate) {
            const dateStr = `${cursor.getFullYear()}-${String(cursor.getMonth()+1).padStart(2,'0')}-${String(cursor.getDate()).padStart(2,'0')}`;
            cursor.setDate(cursor.getDate() + 1);

            // ✅ PRIMARY: SQLite cache (zero Firebase cost)
            const cached = lc.getRegister(gid, dateStr);
            if (cached && cached.length > 0) {
              let ca = 0, reste = 0;
              cached.forEach(e => {
                const paid = (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
                ca += paid;
                const sr = Number(e.reste) || 0;
                if (sr > 0) reste += sr;
                else { const prix = Number(e.prix)||0; if (prix > 0 && prix > paid) reste += prix - paid; }
              });

              // ✅ Subtract approved décaissements (same as KPI endpoint)
              const decs = lc.getDecaissements(gid, dateStr) || [];
              decs.filter(d => d.status === 'approved' || !d.status)
                  .forEach(d => { ca -= Number(d.montant) || 0; });

              if (ca > 0) calendarData[dateStr] = (calendarData[dateStr] || 0) + ca;
              if (reste > 0) resteData[dateStr] = (resteData[dateStr] || 0) + reste;
            }
            // Note: Days with no SQLite data = gym was closed or data not yet synced.
            // We don't fall back to Firestore per-day to avoid quota burn.
            // The nightly register sync will populate SQLite for any missing days.
          }
        }

        return { calendarData, resteData };
      });

      res.json({ ok: true, gymId, year: Number(year), ...result });
    } catch (err) {
      console.error('GET /api/register/calendar error:', err);
      res.status(500).json({ error: 'Failed to fetch calendar' });
    }
  });

  // ── GET /api/register/auralix-analysis ───────────────────────────────────
  // AURALIX AI: Scans the full month's register for a gym and returns:
  //   - reste: unpaid balances
  //   - duplicates: suspect or renewal entries (by CIN/name)
  //   - anomalies: prix=0 entries
  //   - summary: auto-generated French insight text
  router.get('/auralix-analysis', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat', month } = req.query;
      // month format: YYYY-MM (defaults to current month)
      const target = month || (() => {
        const d = new Date();
        return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
      })();

      const gymIds = gymId === 'all' ? ['dokarat','marjane','casa1','casa2'] : [gymId];

      // ── Load all entries for the target month from SQLite ─────────────────
      const phGym = gymIds.map(() => '?').join(',');
      const allEntries = lc.db.prepare(`
        SELECT * FROM register_cache
        WHERE gym_id IN (${phGym})
          AND date >= ? AND date <= ?
        ORDER BY date ASC
      `).all(...gymIds, `${target}-01`, `${target}-31`);

      // ── 1. RESTE EN ATTENTE ───────────────────────────────────────────────
      const resteEntries = allEntries
        .filter(e => Number(e.reste) > 0)
        .map(e => ({
          id: e.id, nom: e.nom, cin: e.cin, tel: e.tel,
          gym_id: e.gym_id, date: e.date,
          reste: Number(e.reste), note: e.note_reste || null,
          prix: Number(e.prix), commercial: e.commercial,
        }));

      // ── 2. DOUBLONS ───────────────────────────────────────────────────────
      const byCin = {};
      const byName = {};
      allEntries.forEach(e => {
        // Group by CIN
        const cin = (e.cin || '').trim().toUpperCase();
        if (cin && cin !== '-' && cin.length > 2) {
          if (!byCin[cin]) byCin[cin] = [];
          byCin[cin].push(e);
        }
        // Group by normalised name (for no-CIN entries)
        const nom = (e.nom || '').trim().toUpperCase().replace(/\s+/g, ' ');
        if (nom) {
          if (!byName[nom]) byName[nom] = [];
          byName[nom].push(e);
        }
      });

      const duplicates = [];

      // CIN-based duplicates
      Object.entries(byCin).forEach(([cin, entries]) => {
        if (entries.length < 2) return;
        // Sort by date
        entries.sort((a, b) => a.date.localeCompare(b.date));
        for (let i = 1; i < entries.length; i++) {
          const prev = entries[i-1], curr = entries[i];
          const daysDiff = Math.round((new Date(curr.date) - new Date(prev.date)) / 86400000);
          const sameGym = prev.gym_id === curr.gym_id;
          const type = (sameGym && daysDiff < 45) ? 'suspect' : 'renouvellement';
          duplicates.push({
            type, cin,
            entries: [prev, curr].map(e => ({
              id: e.id, nom: e.nom, gym_id: e.gym_id, date: e.date,
              prix: Number(e.prix), abonnement: e.abonnement, commercial: e.commercial
            })),
            daysDiff,
            reason: type === 'suspect'
              ? `Même CIN inscrit 2× en ${daysDiff} jours — probable doublon`
              : `Même CIN — renouvellement après ${daysDiff} jours`,
          });
        }
      });

      // Name-only duplicates (no CIN match already found above)
      Object.entries(byName).forEach(([nom, entries]) => {
        if (entries.length < 2) return;
        const hasCin = entries.some(e => {
          const cin = (e.cin||'').trim().toUpperCase();
          return cin && cin !== '-' && cin.length > 2 && byCin[cin]?.length > 1;
        });
        if (hasCin) return; // already captured by CIN logic
        entries.sort((a, b) => a.date.localeCompare(b.date));
        const daysDiff = Math.round((new Date(entries[entries.length-1].date) - new Date(entries[0].date)) / 86400000);
        duplicates.push({
          type: 'nom_seulement',
          cin: null,
          entries: entries.map(e => ({
            id: e.id, nom: e.nom, gym_id: e.gym_id, date: e.date,
            prix: Number(e.prix), abonnement: e.abonnement, commercial: e.commercial
          })),
          daysDiff,
          reason: `Même nom sans CIN — vérification requise`,
        });
      });

      // ── 3. ANOMALIES PRIX ─────────────────────────────────────────────────
      const anomalies = allEntries
        .filter(e => Number(e.prix) === 0 && e.nom && e.nom.trim())
        .map(e => ({
          id: e.id, nom: e.nom, gym_id: e.gym_id, date: e.date,
          abonnement: e.abonnement, commercial: e.commercial,
          reason: 'Prix = 0 DH — inscription sans montant',
        }));

      // ── 4. ANALYSE DIABOLIQUE (NEW) ───────────────────────────────────────
      const devilFindings = [];

      // A. Horaires Suspects (Basé sur les heures d'ouverture MegaFit)
      allEntries.forEach(e => {
        if (e.created_at) {
          const d = new Date(e.created_at);
          const hour = d.getHours();
          const day = d.getDay(); // 0=Sun, 1=Mon, ..., 6=Sat
          const isWeekend = (day === 0 || day === 6);
          
          let isSuspect = false;
          if (isWeekend) {
            // Weekend: Ouvert 06:00 - 22:00
            if (hour < 6 || hour >= 22) isSuspect = true;
          } else {
            // Semaine: Ouvert 06:00 - 00:00
            if (hour < 6) isSuspect = true;
          }

          if (isSuspect) {
            devilFindings.push({ type: 'horaire', entry: e, reason: `Inscription hors horaires (${hour}h) — vérifier l'ouverture du club.` });
          }
        }
      });

      // B. Incohérence de Prix (Même abonnement, prix très différents)
      const subPrices = {};
      allEntries.forEach(e => {
        if (!e.abonnement || !e.prix) return;
        if (!subPrices[e.abonnement]) subPrices[e.abonnement] = [];
        subPrices[e.abonnement].push(Number(e.prix));
      });
      Object.entries(subPrices).forEach(([sub, prices]) => {
        const avg = prices.reduce((a, b) => a + b, 0) / prices.length;
        allEntries.forEach(e => {
          if (e.abonnement === sub && Number(e.prix) < avg * 0.5 && Number(e.prix) > 0) {
            devilFindings.push({ type: 'prix_bas', entry: e, reason: `Prix anormalement bas pour "${sub}" (${e.prix} DH vs moy. ${Math.round(avg)} DH)` });
          }
        });
      });

      // C. Performance Commerciale (Détection de fuites)
      const commStats = {};
      allEntries.forEach(e => {
        const c = e.commercial || 'SANS_COMMERCIAL';
        if (!commStats[c]) commStats[c] = { total: 0, reste: 0, count: 0 };
        commStats[c].total += Number(e.prix) + (Number(e.reste) || 0);
        commStats[c].reste += (Number(e.reste) || 0);
        commStats[c].count++;
      });
      Object.entries(commStats).forEach(([comm, s]) => {
        const resteRatio = s.total > 0 ? (s.reste / s.total) : 0;
        if (resteRatio > 0.4 && s.count > 2) {
          devilFindings.push({ type: 'commercial_debt', comm, reason: `Ratio impayés critique : ${Math.round(resteRatio*100)}% des ventes de ce commercial sont en RESTE.` });
        }
      });

      // ── 5. FINANCIAL HEALTH (Harsher) ─────────────────────────────────────
      const totalReste = resteEntries.reduce((s, e) => s + e.reste, 0);
      const suspectCount = duplicates.filter(d => d.type === 'suspect').length;
      const totalEntries = allEntries.length;

      // Devil Score: harder to get 100
      let score = 100;
      score -= Math.min(35, (totalReste / Math.max(1, totalEntries * 300)) * 100); // penalize by debt volume
      score -= Math.min(30, suspectCount * 10);
      score -= Math.min(20, anomalies.length * 10);
      score -= Math.min(15, devilFindings.length * 3);
      score = Math.max(0, Math.round(score));

      // ── 6. AURALIX INSIGHT TEXT ───────────────────────────────────────────
      const gymName = { dokarat: 'Doukkarate', marjane: 'Marjane', casa1: 'Casa 1', casa2: 'Casa 2' }[gymId] || gymId;
      const monthFr = new Date(`${target}-15`).toLocaleDateString('fr-FR', { month: 'long', year: 'numeric' });

      let insight = '';
      if (resteEntries.length === 0 && suspectCount === 0 && anomalies.length === 0 && devilFindings.length === 0) {
        insight = `✨ ${gymName} — ${monthFr} : Registre impeccable. Analyse diabolique terminée sans faute.`;
      } else {
        const parts = [];
        if (resteEntries.length > 0) parts.push(`${totalReste.toLocaleString()} DH impayés`);
        if (suspectCount > 0) parts.push(`${suspectCount} doublons suspects`);
        if (devilFindings.length > 0) parts.push(`${devilFindings.length} alertes avancées`);
        insight = `😈 Mode "Devil Analyzer" actif : ${parts.join(', ')}. Santé : ${score}/100.`;
      }

      res.json({
        ok: true, gymId, month: target,
        totalEntries, score,
        insight,
        reste: resteEntries,
        duplicates: duplicates.sort((a, b) => (a.type === 'suspect' ? -1 : 1)),
        anomalies,
        devilFindings, // NEW: detailed advanced findings
        stats: {
          totalReste,
          suspectDuplicates: suspectCount,
          renewals: duplicates.filter(d => d.type === 'renouvellement').length,
          nameOnlyDuplicates: duplicates.filter(d => d.type === 'nom_seulement').length,
          prixZero: anomalies.length,
          advancedAlerts: devilFindings.length
        }
      });
    } catch (err) {
      console.error('GET /api/register/auralix-analysis error:', err);
      res.status(500).json({ error: 'Auralix analysis failed' });
    }
  });



  // ── GET /api/register/decaissements-history ───────────────────────────────
  // Returns full history of décaissements (sortie d'espèces) with gym & date range filter.
  // SQLite-first, Firestore fallback, writes through to SQLite on miss.
  router.get('/decaissements-history', verifyAzureToken, async (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    try {
      const { gymId = 'dokarat', startDate, endDate } = req.query;
      if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate required (YYYY-MM-DD)' });

      const gymIds = gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : [gymId];

      // 1️⃣ SQLite primary: fetch all decaissements in date range
      const placeholders = gymIds.map(() => '?').join(',');
      const rows = lc.db.prepare(`
        SELECT * FROM decaissements_cache
        WHERE gym_id IN (${placeholders})
          AND date >= ? AND date <= ?
        ORDER BY date DESC, created_at DESC
      `).all(...gymIds, startDate, endDate);

      // 2️⃣ If SQLite is empty for this range, try Firestore fallback (quota-safe)
      if (rows.length === 0 && !isQuotaExceeded()) {
        try {
          const start = new Date(startDate);
          const end   = new Date(endDate);
          for (const gid of gymIds) {
            const cursor = new Date(start);
            while (cursor <= end) {
              const dateStr = cursor.toISOString().slice(0, 10);
              cursor.setDate(cursor.getDate() + 1);
              const snap = await db.collection('megafit_daily_register')
                .doc(`${gid}_${dateStr}`)
                .collection('decaissements')
                .orderBy('createdAt', 'asc')
                .get();
              if (!snap.empty) {
                const fetched = snap.docs.map(d => ({ id: d.id, ...d.data() }));
                lc.upsertDecaissements(gid, dateStr, fetched);
                fetched.forEach(d => rows.push({ ...d, gym_id: gid, date: dateStr }));
              }
            }
          }
        } catch (fsErr) {
          console.warn('⚠️ [DECAISSEMENTS HISTORY] Firestore fallback failed:', fsErr.message);
        }
      }

      // 3️⃣ Enrich & compute totals (rejected entries shown in table but NOT counted)
      const entries = rows.map(r => ({
        id:          r.id,
        gymId:       r.gym_id,
        date:        r.date,
        montant:     Number(r.montant) || 0,
        raison:      r.raison || '',
        commercial:  r.commercial || '',
        signature:   r.signature || '',
        status:      r.status || 'approved',
        requestedBy: r.requested_by || '',
        approvedBy:  r.approved_by || '',
        createdAt:   r.created_at || '',
      }));

      // Only sum APPROVED — pending and rejected are NOT counted
      const countable = entries.filter(e => e.status === 'approved');
      const total = countable.reduce((sum, e) => sum + e.montant, 0);
      const byGym = {};
      countable.forEach(e => { byGym[e.gymId] = (byGym[e.gymId] || 0) + e.montant; });

      res.json({ ok: true, gymId, startDate, endDate, entries, total, byGym, count: entries.length });
    } catch (err) {
      console.error('GET /api/register/decaissements-history error:', err);
      res.status(500).json({ error: 'Failed to fetch history', entries: [] });
    }
  });

  // ── GET /api/register/search?gymId=dokarat&name=Boulaghnoud ─────────────
  // Returns all register entries matching a member name across all dates.
  // Used by the "Pay Rest" modal to show full payment history.
  router.get('/search', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat', name = '' } = req.query;
      if (!name.trim()) return res.json({ ok: true, entries: [] });

      const searchTerm = `%${name.trim().toLowerCase()}%`;
      const rows = lc.db.prepare(`
        SELECT * FROM register_cache
        WHERE gym_id = ?
          AND (LOWER(nom) LIKE ? OR tel LIKE ?)
        ORDER BY date DESC
        LIMIT 50
      `).all(gymId, searchTerm, searchTerm);

      const entries = rows.map(r => ({
        id: r.id,
        date: r.date,
        gymId: r.gym_id,
        nom: r.nom,
        contrat: r.contrat,
        commercial: r.commercial,
        cin: r.cin,
        tel: r.tel,
        prix: r.prix,
        tpe: r.tpe,
        espece: r.espece,
        virement: r.virement,
        cheque: r.cheque,
        reste: r.reste,
        note_reste: r.note_reste,
        abonnement: r.abonnement
      }));

      res.json({ ok: true, entries });
    } catch (err) {
      console.error('GET /api/register/search error:', err);
      res.status(500).json({ error: 'Search failed', entries: [] });
    }
  });

  // ── DÉCAISSEMENTS ──────────────────────────────────────────────────────────
  
  router.post('/decaissement', verifyAzureToken, async (req, res) => {
    try {
      const { date, gymId = 'dokarat', ...decData } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });
      
      const userRole = req.user?.role || 'manager';
      const status = (userRole === 'admin') ? 'approved' : 'pending';
      const userName = req.user?.preferred_username || req.user?.name || 'system';

      const docId = `${gymId}_${date}`;
      const payload = {
        ...decData,
        location: gymId,
        status: status,
        requestedBy: userName,
        approvedBy: (status === 'approved') ? userName : null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: userName,
      };

      const ref = await db.collection('megafit_daily_register').doc(docId).collection('decaissements').add(payload);
      await db.collection('megafit_daily_register').doc(docId).set({ gymId, date, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      
      const newDoc = await ref.get();
      lc.upsertDecaissements(gymId, date, [{ id: ref.id, ...newDoc.data() }]);
      
      res.json({ ok: true, id: ref.id, status });
    } catch (err) {
      console.error('POST /api/register/decaissement error:', err);
      res.status(500).json({ error: 'Failed to save decaissement' });
    }
  });

  // ── Approval Endpoints ───────────────────────────────────────────────────
  router.patch('/decaissement/:id/approve', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });
      
      const adminName = req.user?.preferred_username || req.user?.name || 'admin';
      const docRef = db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('decaissements').doc(req.params.id);
      
      await docRef.update({
        status: 'approved',
        approvedBy: adminName,
        approvedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      const updated = await docRef.get();
      lc.upsertDecaissements(gymId, date, [{ id: req.params.id, ...updated.data() }]);
      
      res.json({ ok: true });
    } catch (err) {
      console.error('Approve decaissement error:', err);
      res.status(500).json({ error: 'Failed to approve' });
    }
  });

  router.patch('/decaissement/:id/reject', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.body;
      if (!date) return res.status(400).json({ error: 'date required' });
      
      const docRef = db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('decaissements').doc(req.params.id);
      await docRef.update({
        status: 'rejected',
        rejectedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      const updated = await docRef.get();
      lc.upsertDecaissements(gymId, date, [{ id: req.params.id, ...updated.data() }]);
      
      res.json({ ok: true });
    } catch (err) {
      console.error('Reject decaissement error:', err);
      res.status(500).json({ error: 'Failed to reject' });
    }
  });

  router.delete('/decaissement/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { date, gymId = 'dokarat' } = req.query;
      if (!date) return res.status(400).json({ error: 'date required' });
      await db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('decaissements').doc(req.params.id).delete();
      lc.deleteDecaissement(gymId, date, req.params.id);
      
      res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /api/register/decaissement error:', err);
      res.status(500).json({ error: 'Failed to delete decaissement' });
    }
  });

  return router;
};
