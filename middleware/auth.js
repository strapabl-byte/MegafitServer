'use strict';
// middleware/auth.js — Azure Entra ID token verification + role helpers
// Shared by all route files. Never duplicate this logic elsewhere.

const jwt       = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const tenantId = process.env.TENANT_ID;

const jwks = jwksClient({
  // Use 'common' when TENANT_ID is not set (local dev without .env) so JWT
  // signature verification still works against Azure's public keys.
  jwksUri: `https://login.microsoftonline.com/${tenantId || 'common'}/discovery/v2.0/keys`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 60 * 1000, // 10 hours
});

// 🔒 SECURITY: Mapping emails to specific Gym IDs
// Managers will be automatically restricted to these clubs.
const MANAGER_MAPPING = {
  'megafitsaiss@outlook.com':    'marjane',
  'megafitdokkarat@outlook.com': 'dokarat',
  'megafitanfa@outlook.com':     'casa1',   // ✅ Casa Anfa — added 2026-05-07
  'megafitlady@outlook.com':     'casa2',
};

// 🔒 RH — read-only access to all gyms register + decaissements
const RH_EMAILS = [
  'megafitrh@outlook.com',
];

// 🔒 Performance Manager — read-only commercial stats + register (7 days)
const PERF_MANAGER_EMAILS = [
  'performancemanager@outlook.com',
];

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
    if (decoded.tid && tenantId && decoded.tid !== tenantId)
      return res.status(401).json({ error: 'Invalid tenant' });

    // Accept any token from the right tenant:
    // - api:// access token (full setup)
    // - Graph/User.Read access token (fallback while api scope is being configured)
    // - ID token (last resort, aud = clientId)
    const clientId = process.env.CLIENT_ID;
    const aud = Array.isArray(decoded.aud) ? decoded.aud : [decoded.aud];
    const validAuds = [
      clientId,
      `api://${clientId}`,
      'https://graph.microsoft.com',
      '00000003-0000-0000-c000-000000000000' // Graph app ID
    ];
    const audOk = !clientId || aud.some(a => validAuds.some(v => a && a.startsWith(v)));
    if (!audOk) return res.status(401).json({ error: 'Invalid audience' });

    req.user      = decoded;
    const email = (decoded.preferred_username || decoded.upn || decoded.email || '').toLowerCase();
    console.log(`🔐 Auth: Verifying token for ${email}`);
    
    // 🔒 STRICT RBAC: Determine role
    const adminEmails = (process.env.ADMIN_EMAILS || '').toLowerCase().split(',');
    const isExplicitAdmin = adminEmails.includes(email) || (decoded.roles && decoded.roles.includes('Admin')) || decoded.extension_Role === 'admin';
    
    const assignedGym   = MANAGER_MAPPING[email];
    const isRH          = RH_EMAILS.includes(email);
    const isPerfManager = PERF_MANAGER_EMAILS.includes(email);
    
    if (isRH || isPerfManager) {
      // Read-only restricted roles: can access register (all gyms) but not admin routes
      req.isAdmin        = false;
      req.isManager      = true;   // lets existing read-only register routes pass
      req.isRH           = isRH;
      req.isPerfManager  = isPerfManager;
      req.assignedGyms   = ['all'];
    } else if (assignedGym) {
      req.isAdmin   = false;
      req.isManager = true;
      req.assignedGyms = [assignedGym];
    } else if (isExplicitAdmin) {
      req.isAdmin   = true;
      req.isManager = false;
      req.assignedGyms = ['all'];
    } else {
      // Default: Restricted Manager if they have a gym attribute, otherwise Guest (Access Denied)
      req.isAdmin   = false;
      req.isManager = true;
      req.assignedGyms = decoded.extension_Gym ? [decoded.extension_Gym] : [];
    }

    req.hasAccessToGym = (gymId) => {
      if (req.isAdmin || req.assignedGyms.includes('all')) return true;
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
