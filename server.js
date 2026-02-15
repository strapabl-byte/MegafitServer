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
console.log("🔍 Checking for FIREBASE_SERVICE_ACCOUNT env var...");
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.log("✅ FIREBASE_SERVICE_ACCOUNT env var detected.");
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } catch (err) {
    console.error("❌ Failed to parse FIREBASE_SERVICE_ACCOUNT JSON:", err.message);
  }
} else {
  console.log("ℹ️ FIREBASE_SERVICE_ACCOUNT env var is not set.");
}

if (!serviceAccount) {
  try {
    serviceAccount = require("./serviceAccount.json");
    console.log("✅ Loaded credentials from serviceAccount.json file.");
  } catch (err) {
    console.error("❌ No serviceAccount.json file found.");
  }
}

if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "mega-b891d.firebasestorage.app",
  });
  console.log("🚀 Firebase Admin initialized successfully.");
} else {
  console.error("💀 CRITICAL: Firebase Admin NOT initialized. The app will fail to communicate with the database.");
}

const db = admin.firestore();
const bucket = admin.storage().bucket();

// ---------- Azure Entra ID Verification ----------
const tenantId = process.env.TENANT_ID;
const apiClientId = process.env.API_CLIENT_ID;

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

  // 🛠️ DEVELOPMENT BYPASS: Allow demo-token for local testing without Azure config
  if (token === "demo-token") {
    req.user = { id: "demo-admin", name: "Demo Admin", role: "admin" };
    return next();
  }

  // 🔍 DEBUG: Inspect token without verification
  const decodedUntrusted = jwt.decode(token);
  if (decodedUntrusted) {
    console.log("🔍 Token Debug:", {
      aud: decodedUntrusted.aud,
      iss: decodedUntrusted.iss,
      tid: decodedUntrusted.tid,
      ver: decodedUntrusted.ver,
      backendTenant: tenantId
    });
  }

  jwt.verify(
    token,
    getKey,
    { algorithms: ["RS256"] },
    (err, decoded) => {
      if (err) {
        console.error("Azure Token Error:", err.message);
        return res.status(401).json({ error: "Invalid Azure token" });
      }

      if (decoded.tid && decoded.tid !== tenantId) {
        console.error("Azure Token Error: wrong tenant");
        return res.status(401).json({ error: "Invalid tenant" });
      }

      console.log("✅ Azure token OK:", decoded.preferred_username || decoded.name);
      req.user = decoded;
      next();
    }
  );
}

// ---------- File Upload ----------
const upload = multer({ storage: multer.memoryStorage() });

app.post(
  "/api/members/upload",
  verifyAzureToken,
  upload.single("photo"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const ext =
        (req.file.originalname && req.file.originalname.split(".").pop()) || "jpg";
      const fileName = `members/${Date.now()}-${crypto
        .randomUUID()
        .slice(0, 8)}.${ext}`;

      const file = bucket.file(fileName);
      await file.save(req.file.buffer, {
        metadata: { contentType: req.file.mimetype },
        resumable: false,
      });

      const [signedUrl] = await file.getSignedUrl({
        action: "read",
        expires: "2100-01-01",
      });

      res.json({ url: signedUrl });
    } catch (err) {
      console.error("Upload Error:", err);
      res.status(500).json({ error: "Upload failed" });
    }
  }
);

// ---------- ROUTES ----------

// GET Members (with Firestore IDs)
app.get("/api/members", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("members").get();
    const members = snap.docs.map(doc => ({
      id: doc.id,  // ✅ ensure real Firestore ID is returned
      ...doc.data(),
    }));
    res.json(members);
  } catch (err) {
    console.error("Members Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch members" });
  }
});

// CREATE Member + QR
app.post("/api/members", verifyAzureToken, async (req, res) => {
  try {
    const { fullName, phone, plan, birthday, expiresOn, photo } = req.body;
    const qrToken = crypto.randomBytes(16).toString("hex");

    const docRef = await db.collection("members").add({
      fullName,
      phone,
      plan,
      birthday,
      expiresOn,
      photo: photo || null,
      qrCode: null,
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

// GET Single Member
app.get("/api/members/:id", verifyAzureToken, async (req, res) => {
  try {
    const doc = await db.collection("members").doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: "Member not found" });
    res.json({ id: doc.id, ...doc.data() });
  } catch (err) {
    console.error("Fetch Member Error:", err);
    res.status(500).json({ error: "Failed to fetch member" });
  }
});

// UPDATE Member
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
    console.error("Update Member Error:", err);
    res.status(500).json({ error: "Failed to update member" });
  }
});

// ---------- PAYMENTS (Stubs) ----------

app.get("/api/payments/:memberId", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("payments")
      .where("memberId", "==", req.params.memberId)
      .orderBy("date", "desc")
      .get();
    const payments = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(payments);
  } catch (err) {
    console.error("Fetch Payments Error:", err);
    res.status(500).json({ error: "Failed to fetch payments" });
  }
});

app.post("/api/payments", verifyAzureToken, async (req, res) => {
  try {
    const { memberId, amount, plan, date, method } = req.body;
    const docRef = await db.collection("payments").add({
      memberId,
      amount,
      plan,
      date: date || new Date().toISOString(),
      method: method || "Cash",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      recordedBy: req.user?.preferred_username || req.user?.name || "Admin"
    });

    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    console.error("Record Payment Error:", err);
    res.status(500).json({ error: "Failed to record payment" });
  }
});

// DELETE Member (moves data to deleted_members AND users_deleted)
app.delete("/api/members/:id", verifyAzureToken, async (req, res) => {
  const { id } = req.params;

  try {
    const memberRef = db.collection("members").doc(id);
    const memberSnap = await memberRef.get();

    if (!memberSnap.exists) {
      return res.status(404).json({ ok: false, error: "Member not found" });
    }

    const memberData = memberSnap.data();
    const deletedBy = req.user?.preferred_username || req.user?.name || "DashboardAdmin";

    const deletionRecord = {
      ...memberData,
      memberId: id,
      deletedAt: admin.firestore.FieldValue.serverTimestamp(),
      deletedBy,
      backupType: "manual",
    };

    // 1️⃣ Backup to both collections
    await db.collection("deleted_members").doc(id).set(deletionRecord);
    await db.collection("users_deleted").add(deletionRecord); // ✅ Separate backup list for analytics

    // 2️⃣ Clear QR token before deletion (optional extra security)
    await memberRef.update({ qrToken: admin.firestore.FieldValue.delete() });

    // 3️⃣ Delete the member from main collection
    await memberRef.delete();

    // 4️⃣ Log action
    await db.collection("access_logs").add({
      memberId: id,
      usedAt: admin.firestore.FieldValue.serverTimestamp(),
      type: "delete",
      actor: deletedBy,
    });

    console.log(`✅ Member ${id} moved to deleted_members and users_deleted`);
    res.json({ ok: true, message: "Member fully archived and removed" });
  } catch (err) {
    console.error("❌ Delete Member Error:", err);
    res.status(500).json({ ok: false, error: "Failed to delete member" });
  }
});

// ---------- COURSES ----------
// GET Courses
app.get("/api/courses", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("courses").get();
    const courses = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(courses);
  } catch (err) {
    console.error("Courses Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// CREATE Course
app.post("/api/courses", verifyAzureToken, async (req, res) => {
  try {
    const { title, coach, days, time, capacity, reserved } = req.body;
    if (!title || !coach || !days || !time) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const docRef = await db.collection("courses").add({
      title,
      coach,
      days,
      time,
      capacity: Number(capacity) || 20,
      reserved: Number(reserved) || 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user?.preferred_username || req.user?.name || "Admin"
    });

    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    console.error("Create Course Error:", err);
    res.status(500).json({ error: "Failed to create course" });
  }
});

// DELETE Course
app.delete("/api/courses/:id", verifyAzureToken, async (req, res) => {
  try {
    await db.collection("courses").doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    console.error("Delete Course Error:", err);
    res.status(500).json({ error: "Failed to delete course" });
  }
});

// ---------- PUBLIC: Get Courses (for Mobile App) ----------
app.get("/public/courses", async (req, res) => {
  try {
    const snap = await db.collection("courses").get();
    const courses = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(courses);
  } catch (err) {
    console.error("Public Courses Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// ---------- COURSES ----------
// GET Courses
app.get("/api/courses", verifyAzureToken, async (req, res) => {
  try {
    const snap = await db.collection("courses").get();
    const courses = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(courses);
  } catch (err) {
    console.error("Courses Fetch Error:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// CREATE Course
app.post("/api/courses", verifyAzureToken, async (req, res) => {
  try {
    const { title, coach, days, time, capacity, reserved } = req.body;
    if (!title || !coach || !days || !time) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const docRef = await db.collection("courses").add({
      title,
      coach,
      days,
      time,
      capacity: Number(capacity) || 20,
      reserved: Number(reserved) || 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user?.preferred_username || req.user?.name || "Admin"
    });

    const snap = await docRef.get();
    res.json({ id: docRef.id, ...snap.data() });
  } catch (err) {
    console.error("Create Course Error:", err);
    res.status(500).json({ error: "Failed to create course" });
  }
});

// DELETE Course
app.delete("/api/courses/:id", verifyAzureToken, async (req, res) => {
  try {
    await db.collection("courses").doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    console.error("Delete Course Error:", err);
    res.status(500).json({ error: "Failed to delete course" });
  }
});

// ---------- Helper ----------
function daysLeft(expiresOn) {
  if (!expiresOn) return null;
  const today = new Date();
  const t = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const exp = new Date(expiresOn + "T00:00:00");
  return Math.floor((exp - t) / 86400000);
}

// ---------- PUBLIC: verify pass by QR token ----------
app.get("/public/pass/:token", async (req, res) => {
  try {
    const token = req.params.token;
    if (!token) return res.status(400).json({ ok: false, error: "Missing token" });

    // 1️⃣ Find the member with this QR token
    const snap = await db.collection("members")
      .where("qrToken", "==", token)
      .limit(1)
      .get();

    if (snap.empty) {
      // Maybe it's an old token from a deleted user — check backups
      const deletedSnap = await db.collection("users_deleted")
        .where("qrToken", "==", token)
        .limit(1)
        .get();

      if (!deletedSnap.empty) {
        console.log("❌ Access attempt from deleted member (from users_deleted)");
        return res.status(403).json({ ok: false, error: "Member deleted" });
      }

      return res.status(404).json({ ok: false, error: "Pass not found" });
    }

    const docSnap = snap.docs[0];
    const data = docSnap.data();

    // 2️⃣ Extra safety: check if this user was moved to deleted_members
    const deletedRef = db.collection("deleted_members").doc(docSnap.id);
    const deletedDoc = await deletedRef.get();
    if (deletedDoc.exists) {
      console.log("❌ Access attempt from deleted member", docSnap.id);
      return res.status(403).json({ ok: false, error: "Member deleted" });
    }

    // 3️⃣ Expiration & status checks
    const expiresOn = data.expiresOn || null;
    const dLeft = expiresOn ? daysLeft(expiresOn) : null;

    const manualActive = data.status?.active;

    let isActive = true;
    if (manualActive === false) {
      isActive = false;
    } else if (dLeft !== null && dLeft < 0) {
      isActive = false;
    }

    if (!isActive) {
      console.log("⚠️ Inactive/expired member trying to use pass", docSnap.id);
      return res.status(403).json({ ok: false, error: "Membership inactive or expired" });
    }

    // 4️⃣ Delete QR token after first use (one-time access)
    await docSnap.ref.update({
      qrToken: admin.firestore.FieldValue.delete(),
    });

    // 5️⃣ Log access
    await db.collection("access_logs").add({
      memberId: docSnap.id,
      usedAt: admin.firestore.FieldValue.serverTimestamp(),
      type: "qr",
    });

    // 6️⃣ Create Firebase Custom Token so mobile can authenticate
    const firebaseCustomToken = await admin.auth().createCustomToken(docSnap.id);

    // 7️⃣ Return member info + custom token
    const createdAt = data.createdAt?.toDate?.() || null;

    res.json({
      ok: true,
      firebaseCustomToken,
      member: {
        id: docSnap.id,
        fullName: data.fullName || "",
        phone: data.phone || "",
        plan: data.plan || "",
        birthday: data.birthday || null,
        createdAt: createdAt ? createdAt.toISOString() : null,
        expiresOn,
        photo: data.photo || null,
        status: {
          daysLeft: dLeft,
          active: true,
        },
      },
    });
  } catch (err) {
    console.error("QR Pass Lookup Error:", err);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---------- PUBLIC: simple member status check (used by app after QR login) ----------
app.get("/public/member-status/:memberId", async (req, res) => {
  try {
    const { memberId } = req.params;

    if (!memberId) {
      return res.status(400).json({ ok: false, error: "Missing memberId" });
    }

    // ✅ MUST use .get() to obtain a DocumentSnapshot
    const memberRef = db.collection("members").doc(memberId);
    const memberSnap = await memberRef.get();

    // 1️⃣ If not found in members, check deleted_members
    if (!memberSnap.exists) {
      const deletedRef = db.collection("deleted_members").doc(memberId);
      const deletedSnap = await deletedRef.get(); // also a snapshot

      if (deletedSnap.exists) {
        console.log("❌ Status check: member is deleted:", memberId);
        return res.status(404).json({
          ok: false,
          status: "deleted",
          reason: "Member moved to deleted_members",
        });
      }

      console.log("❌ Status check: member not found:", memberId);
      return res.status(404).json({
        ok: false,
        status: "not_found",
        reason: "Member does not exist in members collection",
      });
    }

    const data = memberSnap.data();

    // Reuse same logic as QR endpoint
    const expiresOn = data.expiresOn || null;
    const dLeft = expiresOn ? daysLeft(expiresOn) : null;
    const manualActive = data.status?.active;

    let isActive = true;
    if (manualActive === false) {
      isActive = false;
    } else if (dLeft !== null && dLeft < 0) {
      isActive = false;
    }

    return res.json({
      ok: true,
      memberId,
      status: isActive ? "active" : "inactive",
      daysLeft: dLeft,
      manualActive: manualActive ?? true,
    });
  } catch (err) {
    console.error("Member status error:", err);
    return res.status(500).json({
      ok: false,
      error: "Status endpoint error",
    });
  }
});

// ---------- AI CHAT PROXY ----------
app.post("/api/chat", async (req, res) => {
  console.log("➡️ AI Chat Request received");
  try {
    const { messages } = req.body;
    const GROQ_API_KEY = process.env.GROQ_API_KEY;

    if (!GROQ_API_KEY) {
      console.error("❌ GROQ_API_KEY is missing in process.env");
      return res.status(500).json({ error: "Server Configuration Error: Missing API Key" });
    }

    console.log("🔑 Using API Key length:", GROQ_API_KEY.length);

    console.log("📡 Sending request to Groq... Model: llama-3.3-70b-versatile (Updated)");
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messages,
        model: "llama-3.3-70b-versatile",
        temperature: 0.6,
        max_tokens: 300
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ Groq API Error:", response.status, errorText);
      return res.status(response.status).json({ error: "Groq API Error", details: errorText });
    }

    const data = await response.json();
    console.log("✅ Groq Response received");
    res.json(data);

  } catch (error) {
    console.error("❌ AI Proxy Exception:", error);
    res.status(500).json({ error: "Failed to fetch from AI" });
  }
});

// ---------- START SERVER ----------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("✅ API running on port " + PORT));