'use strict';
// middleware/auth.js — Azure Entra ID token verification + role helpers
// Shared by all route files. Never duplicate this logic elsewhere.

const jwt       = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const tenantId = process.env.TENANT_ID;

const jwks = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 60 * 1000, // 10 hours
});

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return cb(err, null);
    cb(null, key.getPublicKey());
  });
}

function verifyAzureToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  // 🛠️ DEVELOPMENT BYPASS — disabled in production
  if (token === 'demo-token' && process.env.NODE_ENV !== 'production') {
    console.warn('⚠️ [DEV ONLY] demo-token bypass active.');
    req.user = { name: 'Super Admin (Bypass)', oid: 'demo-admin-oid', roles: ['Admin'], preferred_username: 'admin@local.dev' };
    req.isAdmin   = true;
    req.isManager = false;
    req.assignedGyms   = ['all'];
    req.hasAccessToGym = () => true;
    return next();
  }

  if (token === 'demo-token' && process.env.NODE_ENV === 'production') {
    return res.status(401).json({ error: 'demo-token not allowed in production' });
  }

  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    if (decoded.tid && decoded.tid !== tenantId)
      return res.status(401).json({ error: 'Invalid tenant' });

    const adminEmails = (process.env.ADMIN_EMAILS || '')
      .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
    const userEmail = (decoded.preferred_username || decoded.upn || '').toLowerCase();

    req.user      = decoded;
    req.isAdmin   = !decoded.extension_Gym; // true only if no gym restriction (owner)
    req.isManager = !!(decoded.roles?.includes('Manager') || decoded.extension_Role === 'manager' || decoded.extension_Gym);
    req.assignedGyms   = decoded.extension_Gym ? [decoded.extension_Gym] : ['all'];
    req.hasAccessToGym = (gymId) => {
      if (req.assignedGyms.includes('all')) return true;
      return req.assignedGyms.includes(gymId);
    };
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.isAdmin) {
    // Fire-and-forget security audit — never block the response on this
    const { db, admin } = req.app.locals;
    if (db) {
      db.collection('security_audit').add({
        type: '403_FORBIDDEN', path: req.url, method: req.method,
        userOid: req.user?.oid,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});
    }
    return res.status(403).json({ error: 'Access Denied: Admin role required' });
  }
  next();
}

module.exports = { verifyAzureToken, requireAdmin };
