
const admin = require("firebase-admin");
const serviceAccount = require("../serviceAccount.json");

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const db = admin.firestore();

async function checkDoc() {
    const doc = await db.collection("gym_daily_stats").doc("marjane_2026-04-12").get();
    console.log("marjane_2026-04-12 in Firestore:", doc.data());
}

checkDoc();
