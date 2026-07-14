'use strict';
// services/activity-logger.js — one entry point for writing to the manager
// activity audit trail. Writes to BOTH Firestore (`manager_activity_logs`,
// durable + picked up by the nightly sync) AND the SQLite cache
// (`activity_logs_cache`, which the Super Admin / MegaEye feeds read first) using
// the SAME document id, so the event shows up instantly and the sync never
// duplicates it. Fire-and-forget — never blocks the request.

const GYM_CLUBS = {
  dokarat: { id: 'dokarat', name: 'Doukkarate', color: '#10b981' },
  marjane: { id: 'marjane', name: 'Saïss',      color: '#3b82f6' },
  casa1:   { id: 'casa1',   name: 'Casa Anfa',   color: '#f59e0b' },
  casa2:   { id: 'casa2',   name: 'Casa Lady',   color: '#ec4899' },
};

const roleOf = (req) =>
  req.isAdmin ? 'admin' : req.isRH ? 'rh' : req.isPerfManager ? 'performance_manager' : req.isManager ? 'manager' : 'unknown';

// Build the actor object from a verified request.
const userFromReq = (req, path) => ({
  oid:   req.user?.oid,
  name:  req.user?.name || req.user?.preferred_username || req.user?.upn,
  email: req.user?.preferred_username || req.user?.upn || req.user?.email,
  role:  roleOf(req),
  path:  path || (req.originalUrl || '').split('?')[0],
});

// deps: { db, admin, lc }
function logActivity(deps, { action, page = 'Système', gymId = 'system', method = '', source = '', user = {} }) {
  try {
    const { db, admin, lc } = deps;
    const gid = gymId || 'system';
    const id = `${source || 'act'}_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    const club = GYM_CLUBS[gid] || { id: gid, name: gid, color: '#999' };
    const base = {
      action, page, gymId: gid, club,
      userId: user.oid || 'system_id',
      userName: user.name || user.email || 'System',
      userEmail: (user.email || '').toLowerCase(),
      userRole: user.role || 'unknown',
      path: user.path || '',
      method, source,
    };
    // Firestore (durable) — same id as SQLite below
    db.collection('manager_activity_logs').doc(id)
      .set({ ...base, createdAt: admin.firestore.FieldValue.serverTimestamp() })
      .catch((e) => console.warn('[activity-logger] firestore write failed:', e.message));
    // SQLite cache (read-first by the feeds) — instant visibility
    try { lc.upsertActivityLogs([{ id, ...base, createdAt: new Date().toISOString() }]); } catch (_) {}
    return id;
  } catch (e) { console.warn('[activity-logger] error:', e.message); return null; }
}

module.exports = { logActivity, userFromReq, roleOf, GYM_CLUBS };
