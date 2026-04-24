'use strict';
// routes/commercials.js — Commercial Performance & Goals

const { Router } = require('express');
const { verifyAzureToken, requireAdmin } = require('../middleware/auth');

module.exports = function commercialsRouter({ db, admin, lc }) {
  const router = Router();

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/commercials/stats?gymId=dokarat&month=2026-04
  // Reads from SQLite register_cache — zero Firestore reads
  // Returns per-commercial revenue, inscription count, daily breakdown
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/stats', verifyAzureToken, (req, res) => {
    try {
      const { gymId = 'dokarat', month } = req.query;

      // Default to current month
      const now    = new Date();
      const target = month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : gymId.split(',').map(s => s.trim());

      const placeholders = gymIds.map(() => '?').join(',');

      // Aggregate per commercial for the target month — normalize name case+whitespace
      // Exclude: emails (@), OFFERT, MR_ prefix (manager overrides)
      const rows = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial))  AS commercial,
          gym_id,
          COUNT(*)                 AS inscriptions,
          SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) AS revenue,
          MIN(date)                AS first_sale,
          MAX(date)                AS last_sale
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
        GROUP BY UPPER(TRIM(commercial)), gym_id
        ORDER BY revenue DESC
      `).all(...gymIds, `${target}%`);

      // Daily breakdown per commercial — normalized
      const daily = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial))  AS commercial,
          gym_id,
          date,
          COUNT(*)   AS count,
          SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC))  AS revenue
        FROM register_cache
        WHERE gym_id IN (${placeholders})
          AND date LIKE ?
        GROUP BY UPPER(TRIM(commercial)), gym_id, date
        ORDER BY date ASC
      `).all(...gymIds, `${target}%`);

      // ── Alias / typo normalization map ────────────────────────────────────
      // Key = any known variant (already UPPER-TRIMMED), Value = official name
      const CANONICAL = {
        'HAJARE':   'HAJAR',
        'OUISSALE': 'OUISSALE',
        'IMANE':    'IMANE',
        'REDA':     'REDA',
        'ZINEB':    'ZINEB',
        'SABER':    'SABER',
        'AHLALM':   'AHLAM',
      };
      
      function canonical(name) {
        let up = (name || '').trim().toUpperCase();
        
        // Group all empty, dash, or hidden system sales into one visible "AUTRE" category
        if (!up || up === '-' || up === 'NULL' || up.includes('@') || up.startsWith('MR') || ['OFFERT','GRATUIT','TEST','SYSTEM'].includes(up)) {
           return 'AUTRE (SANS NOM)';
        }
        
        return CANONICAL[up] || up; // keep as-is if not in map
      }

      // Build daily map — keyed by canonical name
      const dailyMap = {};
      daily.forEach(r => {
        const key = canonical(r.commercial);
        if (!dailyMap[key]) dailyMap[key] = [];
        dailyMap[key].push({ date: r.date, count: r.count, revenue: r.revenue });
      });

      // Build per-canonical aggregation (merge alias rows)
      const merged = {};
      rows.forEach(r => {
        const name = canonical(r.commercial);
        if (!merged[name]) {
          merged[name] = { name, gymId: r.gym_id, inscriptions: 0, revenue: 0, firstSale: r.first_sale, lastSale: r.last_sale };
        }
        merged[name].inscriptions += r.inscriptions || 0;
        merged[name].revenue      += Math.round(r.revenue || 0);
        // keep earliest firstSale and latest lastSale across aliases
        if (!merged[name].firstSale || r.first_sale < merged[name].firstSale) merged[name].firstSale = r.first_sale;
        if (!merged[name].lastSale  || r.last_sale  > merged[name].lastSale)  merged[name].lastSale  = r.last_sale;
      });

      const stats = Object.values(merged)
        .map(c => ({ ...c, daily: dailyMap[c.name] || [] }))
        .sort((a, b) => b.revenue - a.revenue);

      const rosterRows = lc.db.prepare(`
        SELECT
          UPPER(TRIM(commercial)) AS commercial,
          MAX(date) AS last_sale
        FROM register_cache
        WHERE gym_id IN (${placeholders})
        GROUP BY UPPER(TRIM(commercial))
      `).all(...gymIds);
      
      const rosterMap = {};
      rosterRows.forEach(r => {
         const name = canonical(r.commercial);
         if (!rosterMap[name] || r.last_sale > rosterMap[name].lastSale) {
            rosterMap[name] = { name, lastSale: r.last_sale };
         }
      });
      const roster = Object.values(rosterMap).sort((a,b) => b.lastSale.localeCompare(a.lastSale));

      res.json({ ok: true, month: target, stats, roster });
    } catch (err) {
      console.error('GET /api/commercials/stats error:', err);
      res.status(500).json({ error: 'Erreur lors de la récupération des stats' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/commercials/goals?gymId=dokarat
  // Public read (authenticated) — managers can see too
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/goals', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat' } = req.query;
      const gymIds = gymId === 'all'
        ? ['dokarat', 'marjane', 'casa1', 'casa2']
        : gymId.split(',').map(s => s.trim());

      const snap = await db.collection('commercial_goals')
        .where('gymId', 'in', gymIds)
        .get();
        
      const goals = snap.docs
        .map(d => ({ id: d.id, ...d.data() }))
        .sort((a, b) => (b.period || '').localeCompare(a.period || ''));

      // Dynamically calculate the actual real-time revenue for the Gym and Period
      // This includes ALL commercials (even unspecified or dashes) so the Challenge matches the Register Total perfectly!
      for (let g of goals) {
        if (!g.period) {
          g.currentRevenue = 0; g.currentInscriptions = 0; continue; 
        }
        
        let targetGyms = g.gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : [g.gymId];
        const placeholders = targetGyms.map(() => '?').join(',');
        
        const stats = lc.db.prepare(`
          SELECT 
            COUNT(*) as inscriptions, 
            SUM(CAST(tpe AS NUMERIC) + CAST(espece AS NUMERIC) + CAST(virement AS NUMERIC) + CAST(cheque AS NUMERIC)) as revenue 
          FROM register_cache 
          WHERE gym_id IN (${placeholders}) AND date LIKE ?
        `).get(...targetGyms, `${g.period}%`);
        
        g.currentRevenue = stats.revenue || 0;
        g.currentInscriptions = stats.inscriptions || 0;
      }

      res.json({ ok: true, goals });
    } catch (err) {
      console.error('GET /api/commercials/goals error:', err);
      res.status(500).json({ error: 'Erreur lors de la récupération des objectifs' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // POST /api/commercials/goals — Super Admin only
  // Body: { gymId, period, targetRevenue, targetInscriptions, reward, label }
  // ─────────────────────────────────────────────────────────────────────────────
  router.post('/goals', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const { gymId, period, targetRevenue, targetInscriptions, reward, label } = req.body;
      if (!gymId || !period) return res.status(400).json({ error: 'gymId et period sont obligatoires' });

      const doc = {
        gymId,
        period,          // '2026-04' or '2026-W18' or custom label
        label:           label || period,
        targetRevenue:   Number(targetRevenue) || 0,
        targetInscriptions: Number(targetInscriptions) || 0,
        reward:          reward || '',
        createdBy:       req.user?.preferred_username || 'Admin',
        createdAt:       admin.firestore.FieldValue.serverTimestamp(),
        active:          true,
      };

      const ref = await db.collection('commercial_goals').add(doc);
      res.json({ ok: true, id: ref.id, goal: doc });
    } catch (err) {
      console.error('POST /api/commercials/goals error:', err);
      res.status(500).json({ error: 'Erreur lors de la création de l\'objectif' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // PATCH /api/commercials/goals/:id — Super Admin only
  // ─────────────────────────────────────────────────────────────────────────────
  router.patch('/goals/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      const updates = req.body;
      delete updates.createdAt; delete updates.createdBy;
      await db.collection('commercial_goals').doc(req.params.id).update(updates);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Erreur lors de la mise à jour' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // DELETE /api/commercials/goals/:id — Super Admin only
  // ─────────────────────────────────────────────────────────────────────────────
  router.delete('/goals/:id', verifyAzureToken, requireAdmin, async (req, res) => {
    try {
      await db.collection('commercial_goals').doc(req.params.id).delete();
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Erreur lors de la suppression' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GET /api/commercials — list registered commercial names (legacy)
  // ─────────────────────────────────────────────────────────────────────────────
  router.get('/', verifyAzureToken, async (req, res) => {
    try {
      const { gymId = 'dokarat' } = req.query;
      const snap = await db.collection('gym_commercials').where('gymId', '==', gymId).get();
      const commercials = snap.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      res.json({ ok: true, commercials });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch commercials' });
    }
  });

  return router;
};
