// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const admin = require("firebase-admin");
const multer = require("multer");
const crypto = require("crypto");

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
    serviceAccount = require("./serviceAccount.json");
  } catch (err) {
    console.error("❌ No serviceAccount.json file found and no FIREBASE_SERVICE_ACCOUNT env var set.");
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

  // DELETED: demo-token bypass for production security

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
    const snap = await db.collection("members").get();
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
    res.json({ id: docRef.id, ok: true });
  } catch (err) {
    console.error("Public Inscription Error:", err);
    res.status(500).json({ error: "Failed to submit inscription" });
  }
});

// Admin: List pending inscriptions (Web only)
app.get("/api/inscriptions", verifyAzureToken, async (req, res) => {
  try {
    // Simple query to avoid complex indexing requirements in dev
    const snap = await db.collection("pending_members")
      .where("source", "==", "web")
      .get();

    const data = snap.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .filter(ins => ins.status === "pending" || ins.status === "converted"); // Fixed: Keep converted items for persistent notifications
    // Sort in memory instead
    data.sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));

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
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to update inscription" });
  }
});

// Admin: Delete/Mark as processed
app.delete("/api/inscriptions/:id", verifyAzureToken, async (req, res) => {
  try {
    await db.collection("pending_members").doc(req.params.id).delete();
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

app.post("/api/payments", verifyAzureToken, async (req, res) => {
  try {
    const { memberId, amount, plan, date, method } = req.body;
    const docRef = await db.collection("payments").add({
      memberId, amount, plan, date: date || new Date().toISOString(), method: method || "Cash",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      recordedBy: req.user?.preferred_username || req.user?.name || "Admin"
    });
    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    res.status(500).json({ error: "Failed to record payment" });
  }
});

// Atomic conversion of Web Inscription -> Active Member + First Payment
app.post("/api/payments/complete-inscription", verifyAzureToken, async (req, res) => {
  const { inscriptionId, amount, plan, method, expiresOn, fullName, phone, birthday, photo } = req.body;

  try {
    const inscriptionRef = db.collection("pending_members").doc(inscriptionId);
    const insDoc = await inscriptionRef.get();

    if (!insDoc.exists) {
      return res.status(404).json({ error: "Inscription non trouvée" });
    }

    const insData = insDoc.data();
    const qrToken = crypto.randomBytes(16).toString("hex");

    // 1. Create the Member (allow overrides from dashboard form)
    const memberData = {
      fullName: fullName || `${insData.prenom || ''} ${insData.nom || ''}`.trim(),
      phone: phone || insData.telephone || "",
      plan: plan || "Monthly",
      birthday: birthday || insData.dateNaissance || null,
      expiresOn: expiresOn || new Date(Date.now() + 30 * 86400000).toISOString().split('T')[0],
      photo: photo || insData.profilePicture || null,
      qrToken,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const memberRef = await db.collection("members").add(memberData);

    // 2. Record the Payment
    const paymentData = {
      memberId: memberRef.id,
      amount: Number(amount),
      plan: plan || "Monthly",
      date: new Date().toISOString(),
      method: method || "Espèces",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      recordedBy: req.user?.preferred_username || req.user?.name || "Admin"
    };

    await db.collection("payments").add(paymentData);

    // 3. Delete the Inscription
    await inscriptionRef.delete();

    // 4. Audit Log
    await db.collection("security_audit").add({
      type: "INSCRIPTION_CONVERTED",
      inscriptionId,
      memberId: memberRef.id,
      userOid: req.user?.oid,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      ok: true,
      member: { id: memberRef.id, ...memberData }
    });

  } catch (err) {
    console.error("❌ Conversion Error:", err);
    res.status(500).json({ error: "Échec de l'activation du membre" });
  }
});

// ---------- COURSES ----------

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
app.listen(PORT, () => console.log("✅ API running on port " + PORT));