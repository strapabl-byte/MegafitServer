// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const admin = require("firebase-admin");
const multer = require("multer");
const crypto = require("crypto");
const { syncGymCounts, scheduleNightlySync } = require('./auto_sync');

// ---------- App Setup ----------
const app = express();
const helmet = require("helmet");
app.use(helmet()); // Basic security headers
app.use(cors());
app.use(express.json());

// ---------- Firebase Admin ----------
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } catch (err) {
    console.error("❌ Failed to parse FIREBASE_SERVICE_ACCOUNT JSON:", err.message);
  }
}

if (!serviceAccount) {
  try {
    const fs = require('fs');
    const path = require('path');
    
    const secretPath = "/etc/secrets/serviceAccount.json";
    const localPath = path.join(__dirname, "serviceAccount.json");

    if (fs.existsSync(secretPath)) {
      console.log("📂 Found serviceAccount.json in /etc/secrets/");
      serviceAccount = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
    } else if (fs.existsSync(localPath)) {
      console.log("📂 Found local serviceAccount.json");
      serviceAccount = require(localPath);
    } else {
      console.error(`❌ No serviceAccount.json found at ${secretPath} or ${localPath}`);
      // Log available secrets for debugging
      if (fs.existsSync("/etc/secrets")) {
        console.log("📁 Files in /etc/secrets/:", fs.readdirSync("/etc/secrets"));
      } else {
        console.log("📁 /etc/secrets/ directory does not exist.");
      }
    }
  } catch (err) {
    console.error("❌ Error reading service account file:", err.message);
  }
}

if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "mega-b891d.firebasestorage.app",
  });
  console.log("🚀 Firebase Admin initialized.");
} else {
  console.error("💀 Firebase Admin NOT initialized.");
}

const db = admin.firestore();
const bucket = admin.storage().bucket();

// ---------- Azure Entra ID Verification ----------
const tenantId = process.env.TENANT_ID;
const jwks = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
});

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return cb(err, null);
    cb(null, key.getPublicKey());
  });
}

function verifyAzureToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    console.warn("⚠️ verifyAzureToken: Missing token in header");
    return res.status(401).json({ error: "Missing token" });
  }

  // 🧪 LOCAL DEV BYPASS: Allow predefined mock tokens for easier testing
  const mockUsers = {
    'admin': { name: "Adel", role: "admin" },
    'manager_marjane': { name: "Manager Fès Saiss", role: "manager" },
    'manager2': { name: "Manager Dokkarat", role: "manager" }
  };
  if (token === "demo-token" || mockUsers[token]) {
    req.user = mockUsers[token] || { name: "Demo Admin", role: "admin" };
    req.isAdmin = req.user.role === "admin";
    req.isManager = req.user.role === "manager";
    return next();
  }

  jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
    if (err) {
      console.error("❌ verifyAzureToken: Invalid token", err.message);
      return res.status(401).json({ error: "Invalid token" });
    }
    if (decoded.tid && decoded.tid !== tenantId) {
      console.warn(`⚠️ verifyAzureToken: Invalid tenant ID: ${decoded.tid} vs ${tenantId}`);
      return res.status(401).json({ error: "Invalid tenant" });
    }
    req.user = decoded;

    // Normalize role from Azure claims (Extension or App Role)
    // Adjust these based on your specific Azure Ad setup
    req.isAdmin = decoded.roles?.includes("Admin") || decoded.extension_Role === "admin";
    req.isManager = decoded.roles?.includes("Manager") || decoded.extension_Role === "manager";

    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.isAdmin) {
    console.warn(`🚫 Access Denied: Admin role required for ${req.method} ${req.url} (User: ${req.user?.oid || 'Unknown'})`);
    // Security Audit Log
    db.collection("security_audit").add({
      type: "403_FORBIDDEN",
      path: req.url,
      method: req.method,
      userOid: req.user?.oid,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    }).catch(e => console.error("Audit log failed", e));

    return res.status(403).json({ error: "Access Denied: Admin role required" });
  }
  next();
}

// ---------- Server API Cache ----------
const apiCache = {
  inscriptions: {}, // keyed by gymId (or 'all')
  liveEntries: {},  // keyed by gymId
  dailyStats: {},   // keyed by gymId
  general: {}      // for generic counts and simple flags
};

async function getCachedOrFetch(cacheObj, key, ttlMs, fetchFn) {
  const now = Date.now();
  const entry = cacheObj[key] || { data: null, ts: 0 };
  
  if (entry.data && (now - entry.ts < ttlMs)) {
    console.log(`⚡ [CACHE HIT] Route key '${key}' returned from RAM`);
    return entry.data;
  }
  
  console.log(`🌐 [CACHE MISS] Fetching fresh data for '${key}' from Firebase...`);
  const data = await fetchFn();
  
  cacheObj[key] = { data, ts: now };
  return data;
}

function invalidateCache(cacheObj, key = null) {
  if (key) {
    delete cacheObj[key];
    console.log(`🧹 [CACHE INVALIDATED] Key '${key}'`);
  } else {
    for (let k of Object.keys(cacheObj)) delete cacheObj[k];
    console.log(`🧹 [CACHE CLEAR ALL]`);
  }
}

// ---------- File Upload ----------
const upload = multer({ storage: multer.memoryStorage() });

app.post("/api/members/upload", verifyAzureToken, upload.single("photo"), async (req, res) => {
  try {
    console.log("📸 Received upload request for member photo");
    if (!req.file) {
      console.warn("⚠️ No file in request");
      return res.status(400).json({ error: "No file uploaded" });
    }

    console.log(`📂 File: ${req.file.originalname}, Size: ${req.file.size}, Mime: ${req.file.mimetype}`);

    const ext = (req.file.originalname && req.file.originalname.split(".").pop()) || "jpg";
    const fileName = `members/${Date.now()}-${crypto.randomUUID().slice(0, 8)}.${ext}`;
    const file = bucket.file(fileName);

    console.log(`☁️ Attempting to save to bucket: ${bucket.name}, path: ${fileName}`);

    await file.save(req.file.buffer, {
      metadata: { contentType: req.file.mimetype },
      resumable: false
    });

    console.log("✅ File saved successfully. Generating signed URL...");

    const [signedUrl] = await file.getSignedUrl({
      action: "read",
      expires: "2100-01-01"
    });

    console.log("🔗 Signed URL generated:", signedUrl);
    res.json({ url: signedUrl });
  } catch (err) {
    console.error("❌ Upload Error Detail:", err);
    let detailedError = err.message;
    if (!admin.apps.length) detailedError = "Firebase Admin not initialized (Service Account missing)";
    res.status(500).json({ error: "Upload failed: " + detailedError });
  }
});

// ---------- MEMBER ROUTES ----------

app.get("/api/members", verifyAzureToken, async (req, res) => {
  try {
    const gymId = req.query.gymId;
    let query = db.collection("members");
    if (gymId) {
      query = query.where("location", "==", gymId);
    }
    const snap = await query.get();
    let members = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    // Data Minimization for Managers
    if (!req.isAdmin) {
      members = members.map(m => ({
        id: m.id,
        fullName: m.fullName || `${m.name || ''} ${m.surname || ''}`.trim() || "Inconnu",
        phone: m.phone || "",
        birthday: m.birthday || "", // Fixed: Allow managers to see birthday for Age/Anniv persistence
        expiresOn: m.expiresOn,
        plan: m.plan,
        qrToken: m.qrToken || "",
        image: m.photo || m.image || null,
        isRestricted: true // Flag for UI
      }));
    }

    res.json(members);
  } catch (err) {
    console.error("Members Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch members" });
  }
});

app.post("/api/members", verifyAzureToken, async (req, res) => {
  try {
    const { fullName, phone, plan, birthday, expiresOn, photo } = req.body;

    // Check for existing member by phone to prevent duplicates
    if (phone) {
      const existing = await db.collection("members").where("phone", "==", phone).limit(1).get();
      if (!existing.empty) {
        const m = existing.docs[0].data();
        return res.status(409).json({
          error: "Ce numéro de téléphone est déjà associé à un membre.",
          member: { id: existing.docs[0].id, ...m }
        });
      }
    }

    const qrToken = crypto.randomBytes(16).toString("hex");
    const docRef = await db.collection("members").add({
      fullName,
      phone: phone || null,
      plan: plan || "Monthly",
      birthday: birthday || null,
      expiresOn: expiresOn || new Date(Date.now() + 30 * 86400000).toISOString().split('T')[0],
      photo: photo || null,
      qrToken,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    console.error("Create Member Error:", err);
    res.status(500).json({ error: "Failed to create member" });
  }
});

// ---------- INSCRIPTIONS (Pending Members) ----------

// Public: Generate atomic sequential contract number
app.post("/public/generate-contract", async (req, res) => {
  try {
    const counterRef = db.collection("settings").doc("contractCounter");
    const nextNum = await db.runTransaction(async (t) => {
      const doc = await t.get(counterRef);
      let num = 15000;
      if (!doc.exists) {
        t.set(counterRef, { current: num });
      } else {
        num = doc.data().current + 1;
        t.update(counterRef, { current: num });
      }
      return num;
    });
    const formattedNum = nextNum.toString().padStart(6, '0');
    res.json({ contractNumber: formattedNum });
  } catch(err) {
    console.error("Contract Generate Error:", err);
    res.status(500).json({ error: "Failed to generate contract number" });
  }
});

// Public: Submit from inscription form
app.post("/public/inscriptions", async (req, res) => {
  try {
    const data = req.body;
    const docRef = await db.collection("pending_members").add({
      ...data,
      source: "web",
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    
    // Invalidate the inscriptions cache so pending badge updates instantly
    invalidateCache(apiCache.inscriptions);
    
    res.json({ id: docRef.id, ok: true });
  } catch (err) {
    console.error("Public Inscription Error:", err);
    res.status(500).json({ error: "Failed to submit inscription" });
  }
});

// Admin: List pending inscriptions (Web only)
app.get("/api/inscriptions", verifyAzureToken, async (req, res) => {
  try {
    const gymId = req.query.gymId;
    const cacheKey = gymId || "all";
    
    // Use 30-second cache TTL for inscriptions
    const data = await getCachedOrFetch(apiCache.inscriptions, cacheKey, 30000, async () => {
      let query = db.collection("pending_members")
        .where("source", "==", "web")
        .where("status", "==", "pending"); // Strictly pending
        
      if (gymId) {
        query = query.where("gymId", "==", gymId);
      }
      
      const snap = await query.get();
      const rawData = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      rawData.sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
      return rawData;
    });

    res.json(data);
  } catch (err) {
    console.error("Pending Inscriptions Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch pending inscriptions" });
  }
});

// Admin: Update inscription (e.g., mark as converted)
app.patch("/api/inscriptions/:id", verifyAzureToken, async (req, res) => {
  try {
    const updateData = {
      ...req.body,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };
    await db.collection("pending_members").doc(req.params.id).update(updateData);

    // If a memberId is being set, link any orphan payments created by early validation
    if (req.body.memberId) {
      const orphanPayments = await db.collection("payments").where("inscriptionId", "==", req.params.id).get();
      if (!orphanPayments.empty) {
        const batch = db.batch();
        orphanPayments.forEach(p => {
          // Add the real memberId
          batch.update(p.ref, { memberId: req.body.memberId });
        });
        await batch.commit();
      }
    }

    // Invalidate the inscriptions cache
    invalidateCache(apiCache.inscriptions);

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to update inscription" });
  }
});

// Admin: Delete/Mark as processed
app.delete("/api/inscriptions/:id", verifyAzureToken, async (req, res) => {
  try {
    await db.collection("pending_members").doc(req.params.id).delete();
    
    // Invalidate the inscriptions cache
    invalidateCache(apiCache.inscriptions);
    
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete inscription" });
  }
});

app.get("/api/members/:id", verifyAzureToken, async (req, res) => {
  try {
    const doc = await db.collection("members").doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: "Member not found" });
    res.json({ id: doc.id, ...doc.data() });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch member" });
  }
});

app.put("/api/members/:id", verifyAzureToken, async (req, res) => {
  try {
    const { fullName, phone, plan, birthday, expiresOn, photo, status } = req.body;
    const memberRef = db.collection("members").doc(req.params.id);
    const updateData = {};
    if (fullName !== undefined) updateData.fullName = fullName;
    if (phone !== undefined) updateData.phone = phone;
    if (plan !== undefined) updateData.plan = plan;
    if (birthday !== undefined) updateData.birthday = birthday;
    if (expiresOn !== undefined) updateData.expiresOn = expiresOn;
    if (photo !== undefined) updateData.photo = photo;
    if (status !== undefined) updateData.status = status;
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await memberRef.update(updateData);
    const updatedSnap = await memberRef.get();
    res.json({ id: updatedSnap.id, ...updatedSnap.data() });
  } catch (err) {
    res.status(500).json({ error: "Failed to update member" });
  }
});

app.delete("/api/members/:id", verifyAzureToken, async (req, res) => {
  const { id } = req.params;
  try {
    const memberRef = db.collection("members").doc(id);
    const memberSnap = await memberRef.get();
    if (!memberSnap.exists) return res.status(404).json({ ok: false, error: "Member not found" });
    const memberData = memberSnap.data();
    const deletedBy = req.user?.preferred_username || req.user?.name || "Admin";
    const deletionRecord = { ...memberData, memberId: id, deletedAt: admin.firestore.FieldValue.serverTimestamp(), deletedBy };
    await db.collection("deleted_members").doc(id).set(deletionRecord);
    await db.collection("users_deleted").add(deletionRecord);
    await memberRef.delete();
    await db.collection("access_logs").add({ memberId: id, usedAt: admin.firestore.FieldValue.serverTimestamp(), type: "delete", actor: deletedBy });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: "Failed to delete" });
  }
});

// ---------- PAYMENTS ----------

app.get("/api/payments/:memberId", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection("payments").where("memberId", "==", req.params.memberId).orderBy("date", "desc").get();
    res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  } catch (err) {
    console.error("Payment History Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch payments" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTO-REGISTER CA helper — called on every confirmed payment
// Writes a row to megafit_daily_register so it shows in Registre Journalier
// ─────────────────────────────────────────────────────────────────────────────
function planToAbonnement(plan) {
  const map = { 'Monthly':'1 MOIS','Quarterly':'3 MOIS','Semi-Annual':'6 MOIS','Annual':'1 AN' };
  return map[plan] || plan || '1 AN';
}

async function autoRegisterCA({ gymId='dokarat', date, nom, tel, plan, amount, method, commercial, contrat }) {
  try {
    const methodMap = {
      'Espèces':'espece','Cash':'espece','espece':'espece',
      'TPE':'tpe','Carte Bancaire':'tpe','tpe':'tpe',
      'Virement':'virement','virement':'virement',
      'Chèque':'cheque','Cheque':'cheque','cheque':'cheque',
    };
    const field = methodMap[method] || 'espece';
    const amt   = Number(amount) || 0;
    const today = date || new Date().toISOString().slice(0,10);
    const docId = `${gymId}_${today}`;

    await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
      nom:        nom        || '',
      tel:        tel        || '',
      contrat:    contrat    || '',
      commercial: (commercial || 'FORM').toUpperCase(),
      cin:        '',
      prix:       amt,
      tpe:        field==='tpe'      ? amt : 0,
      espece:     field==='espece'   ? amt : 0,
      virement:   field==='virement' ? amt : 0,
      cheque:     field==='cheque'   ? amt : 0,
      abonnement: planToAbonnement(plan),
      note_reste: '',
      source:     'inscription_auto',
      createdAt:  admin.firestore.FieldValue.serverTimestamp(),
      createdBy:  'auto',
    });

    await db.collection('megafit_daily_register').doc(docId).set(
      { gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
      { merge: true }
    );
    console.log(`✅ AutoRegisterCA: ${nom} | ${amt} DH (${method}) → ${docId}`);
  } catch (err) {
    console.error('⚠️  AutoRegisterCA (non-blocking):', err.message);
  }
}

app.post("/api/payments", verifyAzureToken, async (req, res) => {

  try {
    const { memberId, amount, plan, date, method } = req.body;
    const docRef = await db.collection("payments").add({
      memberId, amount, plan, date: date || new Date().toISOString(), method: method || "Cash",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      recordedBy: req.user?.preferred_username || req.user?.name || "Admin"
    });

    // Fetch member name/phone for the register
    let nom = '', tel = '', loc = 'dokarat';
    try {
      const mSnap = await db.collection('members').doc(memberId).get();
      if (mSnap.exists) { 
        nom = mSnap.data().fullName || ''; 
        tel = mSnap.data().phone || ''; 
        loc = mSnap.data().location || 'dokarat';
      }
    } catch(_) {}

    // Auto-add to daily CA register
    await autoRegisterCA({
      gymId: loc,
      nom, tel, plan, amount, method: method || 'Cash',
      commercial: req.user?.preferred_username || req.user?.name || 'Admin',
      contrat: req.body.contrat || ''
    });

    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    res.status(500).json({ error: "Failed to record payment" });
  }
});


// Admin: Validates payment and updates inscription, but leaves member creation for manual review.
app.post("/api/payments/complete-inscription", verifyAzureToken, async (req, res) => {
  try {
    const { inscriptionId, amount, plan, method, fullName, phone, birthday, expiresOn, photo } = req.body;
    const inscriptionRef = db.collection("pending_members").doc(inscriptionId);
    const insDoc = await inscriptionRef.get();

    // 1. Basic check
    const insData = insDoc.exists ? insDoc.data() : { telephone: phone };
    const finalPhone = phone || insData.telephone;

    // 2. Record Orphan Payment (waiting to be linked)
    await db.collection("payments").add({
      inscriptionId, // Links it to the pending inscription until member is created
      amount: Number(amount),
      plan: plan || "Monthly",
      date: new Date().toISOString(),
      method: method || "Espèces",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      recordedBy: req.user?.preferred_username || req.user?.name || "Admin",
      location: insData.gymId || "dokarat"
    });

    // 3. Auto-register in daily CA
    await autoRegisterCA({
      gymId:      insData.gymId || 'dokarat',
      nom:        `${insData.prenom || ''} ${insData.nom || ''}`.trim() || fullName || '',
      tel:        finalPhone || '',
      plan:       plan || 'Monthly',
      amount,
      method:     method || 'Espèces',
      commercial: insData.commercial || req.user?.preferred_username || req.user?.name || 'FORM',
      contrat:    insData.contractNumber || '',
    });
    // 4. Update inscription flag instead of deleting it
    if (insDoc.exists) {
      await inscriptionRef.update({ 
        payment_validated: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.json({ ok: true, message: "Paiement validé avec succès." });

  } catch (err) {
    console.error("❌ Conversion Error:", err);
    res.status(500).json({ error: "Échec de l'activation" });
  }
});

// 🧠 Senior Dev Cache for Firestore Cost Optimization (Spark Plan)
const liveCountCache = {};

function getMoroccanDateStr() {
  const d = new Date();
  d.setTime(d.getTime() + (60 * 60 * 1000)); // UTC+1
  return d.toISOString().slice(0, 10);
}

app.get("/api/courses", verifyAzureToken, async (req, res) => {
  try {
    const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
    const snap = await db.collection("courses").get();

    const courses = await Promise.all(snap.docs.map(async doc => {
      const data = doc.data();
      const courseRef = doc.ref;

      // Calculate real-time count
      const resSnap = await db.collection("reservations")
        .where("sessionId", "==", doc.id)
        .where("weekday", "==", weekday)
        .where("status", "==", "reserved")
        .get();

      const realTimeCount = resSnap.size;

      // Lazy Sync: Update Firestore if the count in the doc is wrong or missing
      if (data.reserved !== realTimeCount) {
        await courseRef.update({ reserved: realTimeCount, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      }

      return { id: doc.id, ...data, reserved: realTimeCount };
    }));
    res.json(courses);
  } catch (err) {
    console.error("Failed to fetch courses:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

app.post("/api/courses", verifyAzureToken, async (req, res) => {
  try {
    const { title, coach, days, time, capacity } = req.body;
    if (!title || !coach || !days || !time) return res.status(400).json({ error: "Missing fields" });
    const docRef = await db.collection("courses").add({
      title, coach, days, time, capacity: Number(capacity) || 20,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user?.preferred_username || req.user?.name || "Admin"
    });
    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data(), reserved: 0 });
  } catch (err) {
    res.status(500).json({ error: "Failed to create course" });
  }
});

app.put("/api/courses/:id", verifyAzureToken, async (req, res) => {
  try {
    const { title, coach, days, time, capacity } = req.body;
    const courseRef = db.collection("courses").doc(req.params.id);
    const updateData = {};
    if (title !== undefined) updateData.title = title;
    if (coach !== undefined) updateData.coach = coach;
    if (days !== undefined) updateData.days = days;
    if (time !== undefined) updateData.time = time;
    if (capacity !== undefined) updateData.capacity = Number(capacity);
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await courseRef.update(updateData);
    const updatedSnap = await courseRef.get();
    res.json({ id: updatedSnap.id, ...updatedSnap.data() });
  } catch (err) {
    res.status(500).json({ error: "Failed to update course" });
  }
});

app.delete("/api/courses/:id", verifyAzureToken, async (req, res) => {
  try {
    await db.collection("courses").doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete course" });
  }
});

app.get("/api/courses/:id/reservations", verifyAzureToken, async (req, res) => {
  try {
    const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
    const snap = await db.collection("reservations")
      .where("sessionId", "==", req.params.id)
      .where("weekday", "==", weekday)
      .where("status", "==", "reserved")
      .get();
    res.json(snap.docs.map(doc => {
      const data = doc.data();
      return { id: doc.id, memberId: data.memberId, fullName: data.fullName || "Unknown", reservedAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : null };
    }));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch reservations" });
  }
});

app.get("/public/courses", async (req, res) => {
  try {
    const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
    const snap = await db.collection("courses").get();
    const courses = await Promise.all(snap.docs.map(async doc => {
      const data = doc.data();
      const resSnap = await db.collection("reservations")
        .where("sessionId", "==", doc.id)
        .where("weekday", "==", weekday)
        .where("status", "==", "reserved")
        .get();

      const realTimeCount = resSnap.size;
      if (data.reserved !== realTimeCount) {
        await doc.ref.update({ reserved: realTimeCount, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      }

      return { id: doc.id, ...data, reserved: realTimeCount };
    }));
    res.json(courses);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch public courses" });
  }
});

// Manual trigger to sync ALL courses at once
app.post("/api/courses/sync-all", verifyAzureToken, async (req, res) => {
  try {
    const weekday = req.query.weekday !== undefined ? parseInt(req.query.weekday) : new Date().getDay();
    const snap = await db.collection("courses").get();
    let updatedCount = 0;

    for (const doc of snap.docs) {
      const resSnap = await db.collection("reservations")
        .where("sessionId", "==", doc.id)
        .where("weekday", "==", weekday)
        .where("status", "==", "reserved")
        .get();

      await doc.ref.update({
        reserved: resSnap.size,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      updatedCount++;
    }
    res.json({ ok: true, message: `Synced ${updatedCount} courses.` });
  } catch (err) {
    console.error("Global Sync Error:", err);
    res.status(500).json({ error: "Sync failed" });
  }
});

// ---------- COACHES ----------

app.get("/api/coaches", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("coaches").orderBy("createdAt", "desc").get();
    res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  } catch (err) {
    console.error("Coaches Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch coaches" });
  }
});

app.post("/api/coaches", verifyAzureToken, async (req, res) => {
  try {
    const { name, surname, specialty, phone, email, hireDate, bio, photo } = req.body;
    if (!name || !surname || !specialty) return res.status(400).json({ error: "name, surname and specialty are required" });
    const qrToken = crypto.randomBytes(16).toString("hex");
    const docRef = await db.collection("coaches").add({
      name, surname, specialty,
      phone: phone || null,
      email: email || null,
      hireDate: hireDate || null,
      bio: bio || null,
      photo: photo || null,
      qrToken,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user?.preferred_username || req.user?.name || "Admin",
    });
    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    console.error("Create Coach Error:", err);
    res.status(500).json({ error: "Failed to create coach" });
  }
});

app.put("/api/coaches/:id", verifyAzureToken, async (req, res) => {
  try {
    const { name, surname, specialty, phone, email, hireDate, bio, photo } = req.body;
    const ref = db.collection("coaches").doc(req.params.id);
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (surname !== undefined) updateData.surname = surname;
    if (specialty !== undefined) updateData.specialty = specialty;
    if (phone !== undefined) updateData.phone = phone;
    if (email !== undefined) updateData.email = email;
    if (hireDate !== undefined) updateData.hireDate = hireDate;
    if (bio !== undefined) updateData.bio = bio;
    if (photo !== undefined) updateData.photo = photo;
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await ref.update(updateData);
    const snap = await ref.get();
    res.json({ id: snap.id, ...snap.data() });
  } catch (err) {
    console.error("Update Coach Error:", err);
    res.status(500).json({ error: "Failed to update coach" });
  }
});

app.delete("/api/coaches/:id", verifyAzureToken, async (req, res) => {
  try {
    await db.collection("coaches").doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    console.error("Delete Coach Error:", err);
    res.status(500).json({ error: "Failed to delete coach" });
  }
});

// Public: validate coach QR → return Firebase custom token (one-time use)
app.get("/public/coach-pass/:token", async (req, res) => {
  try {
    const token = req.params.token;
    if (!token) return res.status(400).json({ error: "Missing token" });
    const snap = await db.collection("coaches").where("qrToken", "==", token).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "Coach pass not found" });
    const docSnap = snap.docs[0];
    const data = docSnap.data();
    // Invalidate token after first use
    await docSnap.ref.update({ qrToken: admin.firestore.FieldValue.delete() });
    await db.collection("access_logs").add({
      coachId: docSnap.id,
      usedAt: admin.firestore.FieldValue.serverTimestamp(),
      type: "coach_qr"
    });
    const firebaseCustomToken = await admin.auth().createCustomToken(`coach_${docSnap.id}`, { role: "coach" });
    res.json({
      ok: true,
      firebaseCustomToken,
      coach: {
        id: docSnap.id,
        name: data.name,
        surname: data.surname,
        specialty: data.specialty,
      }
    });
  } catch (err) {
    console.error("Coach Pass Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get all members enrolled in this coach's courses
app.get("/api/coaches/:id/participants", verifyAzureToken, async (req, res) => {
  try {
    // 1. Get the coach to know their name (courses are matched by coach name)
    const coachDoc = await db.collection("coaches").doc(req.params.id).get();
    if (!coachDoc.exists) return res.status(404).json({ error: "Coach not found" });
    const coachName = `${coachDoc.data().name} ${coachDoc.data().surname}`.trim();

    // 2. Find all courses by this coach (match by full name OR first name for legacy data)
    const coursesSnap = await db.collection("courses")
      .where("coach", "==", coachName)
      .get();

    // Also try matching by first name only (legacy Courses.jsx used firstName)
    const firstNameSnap = await db.collection("courses")
      .where("coach", "==", coachDoc.data().name)
      .get();

    const courseIds = new Set([
      ...coursesSnap.docs.map(d => d.id),
      ...firstNameSnap.docs.map(d => d.id),
    ]);

    if (courseIds.size === 0) {
      return res.json([]);
    }

    // 3. Get all active reservations for those courses
    const courseIdArr = Array.from(courseIds);
    // Firestore 'in' supports up to 30 items
    const chunks = [];
    for (let i = 0; i < courseIdArr.length; i += 30) chunks.push(courseIdArr.slice(i, i + 30));

    const allReservations = [];
    for (const chunk of chunks) {
      const resSnap = await db.collection("reservations")
        .where("sessionId", "in", chunk)
        .where("status", "==", "reserved")
        .get();
      resSnap.docs.forEach(doc => {
        const d = doc.data();
        allReservations.push({
          id: doc.id,
          memberId: d.memberId,
          fullName: d.fullName || "Unknown",
          courseId: d.sessionId,
          courseName: coursesSnap.docs.find(c => c.id === d.sessionId)?.data()?.title
            || firstNameSnap.docs.find(c => c.id === d.sessionId)?.data()?.title
            || "—",
          weekday: d.weekday,
          reservedAt: d.createdAt?.toDate ? d.createdAt.toDate().toISOString() : null,
        });
      });
    }

    // Deduplicate by memberId (same member could have multiple reservations)
    const seen = new Set();
    const unique = allReservations.filter(r => {
      if (seen.has(r.memberId)) return false;
      seen.add(r.memberId);
      return true;
    });

    res.json(unique);
  } catch (err) {
    console.error("Coach Participants Error:", err);
    res.status(500).json({ error: "Failed to fetch participants" });
  }
});

// Get all reservations across all courses
app.get("/api/reservations-global", verifyAzureToken, async (req, res) => {
  try {
    const resSnap = await db.collection("reservations").orderBy("createdAt", "desc").limit(200).get();

    const data = resSnap.docs.map(doc => {
      const d = doc.data();
      // Serialize Firestore Timestamp to ISO string
      let createdAt = null;
      if (d.createdAt?.toDate) {
        createdAt = d.createdAt.toDate().toISOString();
      } else if (d.createdAt?._seconds) {
        createdAt = new Date(d.createdAt._seconds * 1000).toISOString();
      } else if (doc.createTime) {
        createdAt = doc.createTime.toDate().toISOString();
      }
      return {
        id: doc.id,
        memberId: d.memberId,
        fullName: d.fullName || "Unknown",
        courseTitle: d.courseTitle || "—",
        coachName: d.coach || "—",
        dayName: d.dayName || "—",
        startTime: d.start_time || "—",
        endTime: d.end_time || "—",
        weekday: d.weekday,
        status: d.status,
        createdAt
      };
    });
    res.json(data);
  } catch (err) {
    console.error("Global Reservations Error:", err);
    res.status(500).json({ error: "Failed to fetch global reservations" });
  }
});

// ---------- COACH BILANS (Assessments) ----------

app.get("/api/coach-reservations", verifyAzureToken, async (req, res) => {
  try {
    const { status } = req.query;
    let query = db.collection("coach_reservations");

    if (status && status !== 'both') {
      query = query.where("status", "==", status);
    }

    console.log(`🔍 Fetching bilans for status: ${status}`);
    const snap = await query.get();
    console.log(`📊 Found ${snap.size} documents in Firestore for bilans`);
    const data = snap.docs.map(doc => {
      const d = doc.data();
      // Resolve the actual date — use createTime metadata as fallback
      let resolvedDate = null;
      const raw = d.createdAt;
      if (raw && raw.toDate) {
        resolvedDate = raw.toDate().toISOString(); // Real Firestore Timestamp
      } else if (raw && raw._seconds) {
        resolvedDate = new Date(raw._seconds * 1000).toISOString(); // Serialized timestamp
      } else if (doc.createTime) {
        resolvedDate = doc.createTime.toDate().toISOString(); // Firestore doc metadata fallback
      }
      return { id: doc.id, ...d, createdAt: resolvedDate };
    });

    // Sort by createdAt descending
    data.sort((a, b) => {
      const da = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const db2 = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return db2 - da;
    });

    res.json(data);
  } catch (err) {
    console.error("Fetch Bilans Error:", err);
    res.status(500).json({ error: "Failed to fetch bilans" });
  }
});

app.put("/api/coach-reservations/:id", verifyAzureToken, async (req, res) => {
  try {
    const { status, coachNotes } = req.body;
    const ref = db.collection("coach_reservations").doc(req.params.id);

    const updateData = {};
    if (status) updateData.status = status;
    if (coachNotes !== undefined) updateData.coachNotes = coachNotes;
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    await ref.update(updateData);
    const snap = await ref.get();
    res.json({ id: snap.id, ...snap.data() });
  } catch (err) {
    console.error("Update Bilan Error:", err);
    res.status(500).json({ error: "Failed to update bilan" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DAILY REGISTER — "Registre Journalier des Inscriptions"
// Collection: megafit_daily_register/{gymId}_{date}/entries/{entryId}
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/register?date=2025-01-12&gymId=dokarat
app.get("/api/register", verifyAzureToken, async (req, res) => {
  try {
    const { date, gymId = "dokarat" } = req.query;
    if (!date) return res.status(400).json({ error: "date required (YYYY-MM-DD)" });

    const docId = `${gymId}_${date}`;
    const snap = await db.collection("megafit_daily_register")
      .doc(docId)
      .collection("entries")
      .orderBy("createdAt", "asc")
      .get();

    const entries = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    // Compute daily totals
    const totals = entries.reduce((acc, e) => ({
      tpe:       acc.tpe       + (Number(e.tpe)       || 0),
      espece:    acc.espece    + (Number(e.espece)     || 0),
      virement:  acc.virement  + (Number(e.virement)   || 0),
      cheque:    acc.cheque    + (Number(e.cheque)     || 0),
    }), { tpe: 0, espece: 0, virement: 0, cheque: 0 });
    totals.ca = totals.tpe + totals.espece + totals.virement + totals.cheque;

    // Commercial breakdown
    const byCommercial = {};
    entries.forEach(e => {
      const name = (e.commercial || "").toUpperCase();
      if (!name) return;
      if (!byCommercial[name]) byCommercial[name] = { tpe:0, espece:0, virement:0, cheque:0, total:0 };
      byCommercial[name].tpe      += Number(e.tpe)      || 0;
      byCommercial[name].espece   += Number(e.espece)   || 0;
      byCommercial[name].virement += Number(e.virement) || 0;
      byCommercial[name].cheque   += Number(e.cheque)   || 0;
      byCommercial[name].total    += (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
    });

    res.json({ ok: true, date, gymId, entries, totals, byCommercial });
  } catch (err) {
    console.error("GET /api/register error:", err);
    res.status(500).json({ error: "Failed to fetch register" });
  }
});

// POST /api/register/entry — create new row
app.post("/api/register/entry", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    const { date, gymId = "dokarat", ...entry } = req.body;
    if (!date) return res.status(400).json({ error: "date required" });

    const docId = `${gymId}_${date}`;
    const ref = await db.collection("megafit_daily_register")
      .doc(docId)
      .collection("entries")
      .add({
        ...entry,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: req.user?.preferred_username || req.user?.name || "system"
      });

    // Update the parent doc totals for calendar
    await db.collection("megafit_daily_register").doc(docId).set({
      gymId, date, updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    res.json({ ok: true, id: ref.id });
  } catch (err) {
    console.error("POST /api/register/entry error:", err);
    res.status(500).json({ error: "Failed to save entry" });
  }
});

// PUT /api/register/entry/:id — update a row
app.put("/api/register/entry/:id", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    const { date, gymId = "dokarat", ...entry } = req.body;
    if (!date) return res.status(400).json({ error: "date required" });

    const docId = `${gymId}_${date}`;
    await db.collection("megafit_daily_register")
      .doc(docId)
      .collection("entries")
      .doc(req.params.id)
      .update({ ...entry, updatedAt: admin.firestore.FieldValue.serverTimestamp() });

    res.json({ ok: true });
  } catch (err) {
    console.error("PUT /api/register/entry error:", err);
    res.status(500).json({ error: "Failed to update entry" });
  }
});

// DELETE /api/register/entry/:id
app.delete("/api/register/entry/:id", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    const { date, gymId = "dokarat" } = req.query;
    if (!date) return res.status(400).json({ error: "date required" });

    await db.collection("megafit_daily_register")
      .doc(`${gymId}_${date}`)
      .collection("entries")
      .doc(req.params.id)
      .delete();

    res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/register/entry error:", err);
    res.status(500).json({ error: "Failed to delete entry" });
  }
});

// GET /api/register/calendar?year=2025&gymId=dokarat
// Returns daily CA totals + outstanding reste totals for the heatmap calendar
app.get("/api/register/calendar", verifyAzureToken, async (req, res) => {
  try {
    const { year = new Date().getFullYear(), gymId = "dokarat" } = req.query;
    const prefix = `${gymId}_${year}`;

    const snap = await db.collection("megafit_daily_register")
      .where(admin.firestore.FieldPath.documentId(), ">=", prefix + "-01-01")
      .where(admin.firestore.FieldPath.documentId(), "<=", prefix + "-12-31")
      .get();

    const calendarData = {};
    const resteData = {};

    await Promise.all(snap.docs.map(async parentDoc => {
      const date = parentDoc.id.replace(`${gymId}_`, "");
      const entriesSnap = await parentDoc.ref.collection("entries").get();
      let ca = 0;
      let reste = 0;
      entriesSnap.docs.forEach(d => {
        const e = d.data();
        const paid = (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
        ca += paid;
        const prix = Number(e.prix) || 0;
        if (prix > 0 && prix > paid) reste += (prix - paid);
      });
      calendarData[date] = ca;
      if (reste > 0) resteData[date] = reste;
    }));

    res.json({ ok: true, gymId, year: Number(year), calendarData, resteData });
  } catch (err) {
    console.error("GET /api/register/calendar error:", err);
    res.status(500).json({ error: "Failed to fetch calendar" });
  }
});

// ---------- Commercials Management ----------

// GET /api/commercials?gymId=dokarat
app.get("/api/commercials", verifyAzureToken, async (req, res) => {
  try {
    const { gymId = "dokarat" } = req.query;
    const snap = await db.collection("gym_commercials")
      .where("gymId", "==", gymId)
      .orderBy("name", "asc")
      .get();
      
    const commercials = snap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));
    
    res.json({ ok: true, commercials });
  } catch (err) {
    console.error("GET /api/commercials error:", err);
    res.status(500).json({ error: "Failed to fetch commercials" });
  }
});

// POST /api/commercials
app.post("/api/commercials", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    const { gymId, name } = req.body;
    if (!gymId || !name) return res.status(400).json({ error: "gymId and name required" });

    const docRef = await db.collection("gym_commercials").add({
      gymId,
      name: name.trim().toUpperCase(),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ ok: true, id: docRef.id, name: name.trim().toUpperCase() });
  } catch (err) {
    console.error("POST /api/commercials error:", err);
    res.status(500).json({ error: "Failed to add commercial" });
  }
});

// DELETE /api/commercials/:id
app.delete("/api/commercials/:id", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    await db.collection("gym_commercials").doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/commercials error:", err);
    res.status(500).json({ error: "Failed to delete commercial" });
  }
});


// ---------- LIVE ENTRIES (Door Access Feed) ----------

// Second Firestore instance pointing at megadoor-b3ccb (door access DB)
let doorDb2 = null;
try {
  const doorApp2 = admin.apps.find(a => a.name === 'doorAccess2') 
    || admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: undefined,
      }, 'doorAccess2');
  // Re-use same service account but read from a different project isn't possible
  // Instead we'll use the public REST API for the door project (no index needed via REST runQuery)
} catch(e) { /* already init */ }

const DOOR_PROJECT_ID = process.env.DOOR_FIREBASE_PROJECT_ID || "megadoor-b3ccb";
const DOOR_REST_KEY = process.env.DOOR_FIREBASE_API_KEY;

async function fetchDoorCollection(collectionName, locationTag, limitCount = 50) {
  const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT_ID}/databases/(default)/documents:runQuery?key=${DOOR_REST_KEY}`;
    const now = new Date();
    // Start of today (Morocco time)
    const todayStr = new Date(now.getTime() + 60 * 60 * 1000).toISOString().slice(0, 10);

    const body = {
      structuredQuery: {
        from: [{ collectionId: collectionName }],
        where: {
          fieldFilter: {
            field: { fieldPath: "timestamp" },
            op: "GREATER_THAN_OR_EQUAL",
            value: { stringValue: todayStr }
          }
        },
        orderBy: [
          {
            field: { fieldPath: "timestamp" },
            direction: "DESCENDING"
          }
        ],
        limit: 1000 // Increased to handle busy days (Dokkarat had 433+ today)
      }
    };

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const data = await resp.json();
  if (!Array.isArray(data)) return [];

  // DEBUG LOG: See what's actually in this collection
  if (collectionName.includes("saiss")) {
      console.log(`🔍 [DEBUG SAISS] Sample entry from ${collectionName}:`, JSON.stringify(data[0]?.document?.fields?.location || "NO_LOCATION_FIELD"));
  }

  const docs = data
    .filter(item => item.document)
    .map(item => {
      const f = item.document.fields || {};
      const pushedAt = f.pushed_at?.timestampValue || null;
      const timestamp = f.timestamp?.stringValue || null;

      // Resolve display time
      let sortKey = "";
      let displayTime = "--:--";
      if (pushedAt) {
        const d = new Date(pushedAt);
        sortKey = d.toISOString();
        displayTime = d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", timeZone: "Africa/Casablanca" });
      } else if (timestamp) {
        sortKey = timestamp;
        displayTime = timestamp.split(" ")[1]?.slice(0, 5) || "--:--";
      }

      const method = f.method?.stringValue || "";
      return {
        docId: item.document.name.split("/").pop(),
        name: f.name?.stringValue || "Anonyme",
        userId: f.user_id?.stringValue || "",
        status: f.status?.stringValue || "Entrée",
        method,
        location: f.location?.stringValue || "",
        sortKey,
        displayTime,
        isFace: method.toLowerCase().includes("face") || method.toLowerCase().includes("visage")
      };
    })
    .filter(d => {
        if (!d.sortKey) return false;
        const loc = d.location.toLowerCase().trim();
        const target = locationTag.toLowerCase().trim();
        return loc === target || loc.includes(target) || target.includes(loc);
    })
    .sort((a, b) => b.sortKey.localeCompare(a.sortKey))
    .slice(0, limitCount);

  return docs;
}

// GET /api/live-entries?gymId=dokarat|marjane&limit=20
app.get("/api/live-entries", verifyAzureToken, async (req, res) => {
  try {
    const { gymId, limit: limitParam } = req.query;
    const limitCount = parseInt(limitParam) || 50; // Optimized default limit

    const gymMap = {
      dokarat: { collection: "mega_fit_logs", locationTag: "dokkarat fes" },
      marjane: { collection: "saiss entrees logs", locationTag: "fes saiss" }
    };

    const gym = gymMap[gymId];
    if (!gym) {
      return res.status(400).json({ error: "Unknown gymId. Use 'dokarat' or 'marjane'." });
    }

    const cacheKey = `${gymId}_limit_${limitCount}`; 
    const entries = await getCachedOrFetch(apiCache.liveEntries, cacheKey, 15000, async () => {
      return await fetchDoorCollection(gym.collection, gym.locationTag, limitCount);
    });
    
    res.json({ ok: true, gymId, count: entries.length, entries });
  } catch (err) {
    console.error("❌ Live Entries Error:", err);
    res.status(500).json({ error: "Failed to fetch live entries" });
  }
});

// NEW: Ultra-efficient endpoint — reads daily_total & daily_unique from the LATEST doc only
// The access control device embeds running counters in every entry, so 1 read = perfect accuracy
app.get("/api/live-count", verifyAzureToken, async (req, res) => {
  try {
    const { gymId } = req.query;
    if (!gymId) return res.status(400).json({ error: "gymId required" });

    const gymMap = {
      dokarat: { collection: "mega_fit_logs", locationTag: "dokkarat fes" },
      marjane: { collection: "saiss entrees logs", locationTag: "fes saiss" }
    };
    const gym = gymMap[gymId];
    if (!gym) return res.status(400).json({ error: "Invalid gymId" });

    const cacheKey = `live_count_${gymId}`;
    const result = await getCachedOrFetch(apiCache.general, cacheKey, 15000, async () => {
      const todayStr = getMoroccanDateStr();
      const url = `https://firestore.googleapis.com/v1/projects/${DOOR_PROJECT_ID}/databases/(default)/documents:runQuery?key=${DOOR_REST_KEY}`;

      // 🎯 Fetch only the LATEST 1 document — device embeds daily_total & daily_unique counters
      const body = {
        structuredQuery: {
          from: [{ collectionId: gym.collection }],
          where: {
            fieldFilter: {
              field: { fieldPath: "timestamp" },
              op: "GREATER_THAN_OR_EQUAL",
              value: { stringValue: todayStr }
            }
          },
          orderBy: [{ field: { fieldPath: "timestamp" }, direction: "DESCENDING" }],
          limit: 1
        }
      };

      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const data = await resp.json();

      if (!Array.isArray(data) || !data[0]?.document) {
        console.log(`[${gymId}] No entries today yet`);
        return { count: 0, rawCount: 0, date: todayStr };
      }

      const f = data[0].document.fields || {};
      const loc = (f.location?.stringValue || "").toLowerCase().trim();
      const targetLoc = gym.locationTag.toLowerCase().trim();

      // Verify this latest doc belongs to this gym's location
      if (loc !== targetLoc && !loc.includes(targetLoc) && !targetLoc.includes(loc)) {
        console.warn(`[${gymId}] Latest doc location mismatch: "${loc}" vs "${targetLoc}"`);
        return { count: 0, rawCount: 0, date: todayStr };
      }

      // ✅ Read running counters embedded by the device
      const parseNum = (field) => {
        if (!field) return 0;
        if (field.integerValue) return parseInt(field.integerValue);
        if (field.doubleValue) return Math.round(field.doubleValue);
        return 0;
      };

      const dailyUnique = parseNum(f.daily_unique);
      const dailyTotal  = parseNum(f.daily_total);

      console.log(`✅ [${gymId}] daily_unique=${dailyUnique} daily_total=${dailyTotal} (1 read)`);

      return {
        count:    dailyUnique,  // unique people today (device-deduped)
        rawCount: dailyTotal,   // all scans including re-entries
        date: todayStr
      };
    });

    res.json({ ok: true, gymId, ...result });
  } catch (err) {
    console.error("❌ Live Count Error:", err);
    res.status(500).json({ error: "Failed to fetch count" });
  }
});

// ---------- ANALYTICS ----------


app.get("/api/analytics/daily-stats/:gymId", verifyAzureToken, async (req, res) => {
  try {
    const { gymId } = req.params;
    
    const data = await getCachedOrFetch(apiCache.dailyStats, gymId, 300000, async () => {
      console.log(`📊 Fetching daily stats for ${gymId} from DB...`);
      const snap = await db.collection("gym_daily_stats")
        .where("gym_id", "==", gymId)
        .limit(40) // ✅ Fetch 40 to guarantee we always have the last 30 days
        .get();

      let snapData = snap.docs.map(doc => doc.data());
      
      // Filter out invalid records, sort descending to pick 30 most recent
      snapData = snapData.filter(d => d && d.date);
      snapData.sort((a, b) => b.date.localeCompare(a.date)); // newest first
      snapData = snapData.slice(0, 30);  // take 30 most recent
      
      // Reverse for the chart (oldest on left → newest on right)
      snapData.reverse();
      return snapData;
    });
    
    console.log(`✅ Returned ${data.length} days of stats for ${gymId}`);
    res.json(data);
  } catch (err) {
    console.error("Daily Stats Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch analytics" });
  }
});

// Admin-only: Manually trigger a stats sync (handles catching up missed days)
app.post("/api/admin/sync-stats", verifyAzureToken, requireAdmin, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    console.log(`📡 Manual sync requested for last ${days} days...`);
    await syncGymCounts(db, apiCache, days);
    res.json({ ok: true, message: `Sync completed for the last ${days} days.` });
  } catch (err) {
    console.error("Manual Sync Error:", err);
    res.status(500).json({ error: "Sync failed: " + err.message });
  }
});

app.post("/api/analytics/log-entry", verifyAzureToken, async (req, res) => {
  try {
    const { gymId, userId } = req.body;
    if (!gymId) return res.status(400).json({ error: "gymId is required" });
    if (!userId) return res.status(400).json({ error: "userId is required for deduplication" });

    // Use current date for the entry (local time string format YYYY-MM-DD)
    const now = new Date();
    const todayStr = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;

    const docId = `${gymId}_${todayStr}`;
    const docRef = db.collection("gym_daily_stats").doc(docId);
    const visitorRef = docRef.collection("visitors").doc(userId);

    await db.runTransaction(async (t) => {
      const doc = await t.get(docRef);
      const visitorDoc = await t.get(visitorRef);
      const nowTs = Date.now();
      
      let shouldIncrement = true;
      if (visitorDoc.exists) {
        const lastScannedAt = visitorDoc.data().lastScannedAt;
        const lastTs = lastScannedAt.toDate().getTime();
        // 10 minute window (600,000 ms)
        if (nowTs - lastTs < 600000) {
          shouldIncrement = false;
          console.log(`🛡️ Deduplicated scan for ${userId} at ${gymId} (within 10m)`);
        }
      }

      if (shouldIncrement) {
        if (!doc.exists) {
          t.set(docRef, {
            gym_id: gymId,
            date: todayStr,
            count: 1,
            lastSyncedAt: admin.firestore.FieldValue.serverTimestamp()
          });
        } else {
          t.update(docRef, {
            count: (doc.data().count || 0) + 1,
            lastSyncedAt: admin.firestore.FieldValue.serverTimestamp()
          });
        }
        // Update/Set lastScannedAt for the visitor
        t.set(visitorRef, {
          userId,
          lastScannedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        
        console.log(`📈 Incremented entries for ${gymId} - User: ${userId}`);
      }
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Log Entry Error:", err);
    res.status(500).json({ error: "Failed to log entry" });
  }
});

// ---------- HELPERS ----------

function daysLeft(expiresOn) {
  if (!expiresOn) return null;
  const today = new Date();
  const t = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const exp = new Date(expiresOn + "T00:00:00");
  return Math.floor((exp - t) / 86400000);
}

// ---------- PUBLIC AUTH/STATUS ----------

app.get("/public/pass/:token", async (req, res) => {
  try {
    const token = req.params.token;
    if (!token) return res.status(400).json({ error: "Missing token" });
    const snap = await db.collection("members").where("qrToken", "==", token).limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "Pass not found" });
    const docSnap = snap.docs[0];
    const data = docSnap.data();
    const dLeft = data.expiresOn ? daysLeft(data.expiresOn) : null;
    if (data.status?.active === false || (dLeft !== null && dLeft < 0)) return res.status(403).json({ error: "Inactive membership" });
    await docSnap.ref.update({ qrToken: admin.firestore.FieldValue.delete() });
    await db.collection("access_logs").add({ memberId: docSnap.id, usedAt: admin.firestore.FieldValue.serverTimestamp(), type: "qr" });
    const firebaseCustomToken = await admin.auth().createCustomToken(docSnap.id);
    res.json({ ok: true, firebaseCustomToken, member: { id: docSnap.id, fullName: data.fullName, expiresOn: data.expiresOn, status: { daysLeft: dLeft, active: true } } });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/public/member-status/:memberId", async (req, res) => {
  try {
    const { memberId } = req.params;
    const doc = await db.collection("members").doc(memberId).get();
    if (!doc.exists) return res.status(404).json({ ok: false, status: "not_found" });
    const data = doc.data();
    const dLeft = data.expiresOn ? daysLeft(data.expiresOn) : null;
    const isActive = data.status?.active !== false && (dLeft === null || dLeft >= 0);
    res.json({ ok: true, memberId, status: isActive ? "active" : "inactive", daysLeft: dLeft });
  } catch (err) {
    res.status(500).json({ error: "Status endpoint error" });
  }
});

app.post("/api/chat", verifyAzureToken, async (req, res) => {
  try {
    const { messages } = req.body;
    const GROQ_API_KEY = process.env.GROQ_API_KEY;
    if (!GROQ_API_KEY) return res.status(500).json({ error: "Missing API Key" });
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Authorization": `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ messages, model: "llama-3.3-70b-versatile", temperature: 0.6, max_tokens: 300 })
    });
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "AI Proxy failed" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log('✅ API running on port ' + PORT);
  scheduleNightlySync(db, apiCache); // Runs at 00:05 Morocco time
});