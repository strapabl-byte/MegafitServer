// seed_register.js — populate megafit_daily_register with sample data
// Run: node seed_register.js
// Seeds March + April 2026 for gym dokarat

const admin = require("firebase-admin");
const path  = require("path");
const fs    = require("fs");

// ── Firebase init ──────────────────────────────────────────────────────────
const saPath = path.join(__dirname, "serviceAccount.json");
if (!fs.existsSync(saPath)) { console.error("❌ serviceAccount.json not found"); process.exit(1); }
const serviceAccount = require(saPath);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ── Sample data ────────────────────────────────────────────────────────────
const NOMS = [
  "KARIM BENALI", "SARA EL AMRANI", "YOUSSEF TAHIRI", "FATIMA ZOHRA IDRISSI",
  "HAMZA BENMOUSSA", "NADIA CHAOUI", "OMAR SEDDIKI", "LAYLA BERRADA",
  "MEHDI ALAOUI", "KHADIJA BENOMAR", "AMINE CHAKIR", "SALMA OUALI",
  "TARIQ BENNIS", "HIND MANSOURI", "RACHID ZEMMOURI", "IMANE TAZI",
  "BILAL EL FASSI", "SOUKAINA HAJJI", "ADIL LAMRANI", "MERIEM BOUHSSINA",
  "HASSAN CHRAIBI", "ZINEB KETTANI", "MOUAD BELHAJ", "RANIA SEBTI",
  "KHALID OUAZZANI", "LOUBNA BENKIRANE", "AYOUB FILALI", "NOUR BENSAID",
  "ZAKARIA RHAZI", "AMINA TAHIRI",
];
const COMMERCIALS = ["KHALID", "SARA", "AMINE", "FORM", "FORM", "KHALID"];
const ABONNEMENTS = ["1 MOIS","1 MOIS","3 MOIS","6 MOIS","1 AN","1 AN","2 ANS"];
const METHODS = ["espece","espece","tpe","tpe","virement","cheque"];
const PLANS_PRIX = {
  "1 MOIS": 300, "3 MOIS": 800, "6 MOIS": 1500, "1 AN": 2500, "2 ANS": 4500
};

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function phone() { return `06${rand(10,99)}${rand(100000,999999)}`; }
function cin() {
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  return `${letters[rand(0,25)]}${rand(100000,999999)}`;
}

// Build date list: all days in March + April 2026
// Skip some days (gym closed ~8 days/month, so 70% chance of activity per day)
const dates = [];
for (let m = 3; m <= 4; m++) {
  const daysInMonth = m === 3 ? 31 : 30;
  for (let d = 1; d <= daysInMonth; d++) {
    const dd = String(d).padStart(2,"0");
    const mm = String(m).padStart(2,"0");
    if (Math.random() < 0.75) dates.push(`2026-${mm}-${dd}`);
  }
}

async function seedDay(date) {
  const gymId = "dokarat";
  const docId = `${gymId}_${date}`;
  const entriesRef = db.collection("megafit_daily_register").doc(docId).collection("entries");

  // 2-7 inscriptions per day
  const count = rand(2, 7);
  const batch = db.batch();

  for (let i = 0; i < count; i++) {
    const abonnement = pick(ABONNEMENTS);
    const prix = PLANS_PRIX[abonnement] || 300;
    const method = pick(METHODS);

    // 30% chance client pays only part upfront (reste scenario)
    const hasReste = Math.random() < 0.30;
    let paid = prix;
    if (hasReste) {
      // Pay between 50% and 90% of price
      paid = Math.round(prix * (0.5 + Math.random() * 0.4) / 100) * 100;
      paid = Math.max(paid, 100);
    }

    const entry = {
      nom:        pick(NOMS),
      tel:        phone(),
      cin:        cin(),
      contrat:    `C-${date.replace(/-/g,"")}-${String(i+1).padStart(2,"0")}`,
      commercial: pick(COMMERCIALS),
      prix:       prix,
      tpe:        method === "tpe"      ? paid : 0,
      espece:     method === "espece"   ? paid : 0,
      virement:   method === "virement" ? paid : 0,
      cheque:     method === "cheque"   ? paid : 0,
      abonnement,
      note_reste: hasReste ? `Reste ${prix - paid} DH à encaisser` : "",
      source:     "seed",
      createdAt:  admin.firestore.Timestamp.fromDate(new Date(`${date}T10:00:00`)),
      createdBy:  "seed_script",
    };

    const ref = entriesRef.doc();
    batch.set(ref, entry);
  }

  await batch.commit();

  // Update parent doc
  await db.collection("megafit_daily_register").doc(docId).set({
    gymId, date, updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  const ca = count * 1000; // rough
  console.log(`✅ ${date} — ${count} inscriptions`);
}

async function main() {
  console.log(`🌱 Seeding ${dates.length} days for Mars + Avril 2026...\n`);
  for (const date of dates) {
    await seedDay(date);
  }
  console.log("\n🎉 Done! Refresh the Registre page and check the calendar.");
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
