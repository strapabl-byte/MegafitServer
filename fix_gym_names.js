const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const gyms = {
  dokarat: 'MEGAFIT DOKKARAT',
  marjane: 'MEGAFIT SAISS / MARJANE',
  casa1:   'MEGAFIT ANFA',
  casa2:   'MEGAFIT LADY ANFA'
};

async function fix() {
  for (const [id, name] of Object.entries(gyms)) {
    console.log("Fixing " + id + " -> " + name);
    await db.collection("config").doc("inscription-" + id).set({
      gymId: id,
      gymName: name,
      updatedAt: new Date().toISOString()
    }, { merge: true });
  }
  process.exit(0);
}

fix();
