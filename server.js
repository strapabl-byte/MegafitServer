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

  if (!token) return res.status(401).json({ error: "Missing token" });

  if (token === "demo-token") {
    req.user = { id: "demo-admin", name: "Demo Admin", role: "admin" };
    return next();
  }

  jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    if (decoded.tid && decoded.tid !== tenantId) return res.status(401).json({ error: "Invalid tenant" });
    req.user = decoded;
    next();
  });
}

// ---------- File Upload ----------
const upload = multer({ storage: multer.memoryStorage() });

app.post("/api/members/upload", verifyAzureToken, upload.single("photo"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const ext = (req.file.originalname && req.file.originalname.split(".").pop()) || "jpg";
    const fileName = `members/${Date.now()}-${crypto.randomUUID().slice(0, 8)}.${ext}`;
    const file = bucket.file(fileName);
    await file.save(req.file.buffer, { metadata: { contentType: req.file.mimetype }, resumable: false });
    const [signedUrl] = await file.getSignedUrl({ action: "read", expires: "2100-01-01" });
    res.json({ url: signedUrl });
  } catch (err) {
    console.error("Upload Error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// ---------- MEMBER ROUTES ----------

app.get("/api/members", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("members").get();
    const members = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
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
      fullName, phone, plan, birthday, expiresOn, photo: photo || null, qrToken,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    console.error("Create Member Error:", err);
    res.status(500).json({ error: "Failed to create member" });
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

app.get("/api/payments/:memberId", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("payments").where("memberId", "==", req.params.memberId).orderBy("date", "desc").get();
    res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  } catch (err) {
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

// ---------- COURSES ----------

app.get("/api/courses", verifyAzureToken, async (req, res) => {
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
      return { id: doc.id, ...data, reserved: resSnap.size };
    }));
    res.json(courses);
  } catch (err) {
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
      return { id: doc.id, ...data, reserved: resSnap.size };
    }));
    res.json(courses);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch public courses" });
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

app.post("/api/chat", async (req, res) => {
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