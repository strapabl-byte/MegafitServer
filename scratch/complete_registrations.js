
const admin = require("firebase-admin");
const serviceAccount = require("../serviceAccount.json");
const crypto = require("crypto");

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const db = admin.firestore();

async function run() {
    const today = "2026-04-12";
    const gymId = "dokarat";
    const docId = `${gymId}_${today}`;

    // 1. Add Youssef El Amrani
    console.log("Adding Youssef El Amrani...");
    const qr1 = crypto.randomBytes(16).toString("hex");
    const m1 = await db.collection("members").add({
        fullName: "YOUSSEF EL AMRANI",
        phone: "0661234567",
        cin: "BK123456",
        plan: "Annual",
        birthday: "1995-05-15",
        expiresOn: "2027-04-12",
        qrToken: qr1,
        gymId: gymId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("payments").add({
        memberId: m1.id,
        memberName: "YOUSSEF EL AMRANI",
        amount: 3000,
        method: "ESPECE",
        date: today,
        gymId: gymId,
        note: "Subscription Annual",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("megafit_daily_register")
        .doc(docId)
        .collection("entries")
        .add({
            contrat: "BK-123",
            commercial: "MAROUANE",
            nom: "YOUSSEF EL AMRANI",
            cin: "BK123456",
            tel: "0661234567",
            prix: 3000,
            espece: 3000,
            abonnement: "1 AN",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

    // 2. Add Sarah Bennani
    console.log("Adding Sarah Bennani...");
    const qr2 = crypto.randomBytes(16).toString("hex");
    const m2 = await db.collection("members").add({
        fullName: "SARAH BENNANI",
        phone: "0667890123",
        cin: "CD789012",
        plan: "6 Months",
        birthday: "1998-09-20",
        expiresOn: "2026-10-12",
        qrToken: qr2,
        gymId: gymId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("payments").add({
        memberId: m2.id,
        memberName: "SARAH BENNANI",
        amount: 500,
        method: "ESPECE",
        date: today,
        gymId: gymId,
        note: "Partial payment (Total 1800)",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("megafit_daily_register")
        .doc(docId)
        .collection("entries")
        .add({
            contrat: "CD-456",
            commercial: "MAROUANE",
            nom: "SARAH BENNANI",
            cin: "CD789012",
            tel: "0667890123",
            prix: 1800,
            espece: 500,
            abonnement: "6 MOIS",
            note_reste: "Reste 1300 DH",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

    // Update parent doc for calendar heatmap
    await db.collection("megafit_daily_register").doc(docId).set({
        gymId, date: today, updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log("Done! Both members are now in the dashboard.");
}

run().catch(console.error);
