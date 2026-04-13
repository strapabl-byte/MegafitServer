
const admin = require("firebase-admin");
const serviceAccount = require("../serviceAccount.json");

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const db = admin.firestore();

async function check() {
    const today = "2026-04-12";
    const gymId = "dokarat";
    const docId = `${gymId}_${today}`;

    console.log("--- Members ---");
    const mSnap = await db.collection("members")
        .where("fullName", "in", ["YOUSSEF EL AMRANI", "SARAH BENNANI"])
        .get();
    mSnap.forEach(d => console.log(d.id, "=>", d.data().fullName, "(Phone:", d.data().phone, ")"));

    console.log("\n--- Payments ---");
    const pSnap = await db.collection("payments")
        .where("date", "==", today)
        .where("gymId", "==", gymId)
        .get();
    pSnap.forEach(d => console.log(d.id, "=>", d.data().memberName, d.data().amount, "DH"));

    console.log("\n--- Daily Register (Entries) ---");
    const rSnap = await db.collection("megafit_daily_register")
        .doc(docId)
        .collection("entries")
        .get();
    rSnap.forEach(d => console.log(d.id, "=>", d.data().nom, "| Contrat:", d.data().contrat, "| Paid:", d.data().espece, "DH"));
}

check();
