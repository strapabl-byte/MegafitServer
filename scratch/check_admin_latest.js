const admin = require('firebase-admin');
const path = require('path');
const serviceAccount = require('../serviceAccount.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

async function check() {
  console.log("Fetching latest 10 entries from doukkarate_door_entries...");
  const snap = await db.collection('doukkarate_door_entries')
                      .orderBy('timestamp', 'desc')
                      .limit(10)
                      .get();
  
  if (snap.empty) {
    console.log("No entries found!");
    return;
  }

  snap.forEach(doc => {
    const data = doc.data();
    console.log(`[${data.timestamp}] ${data.name} | Loc: ${data.location} | Unique: ${data.daily_unique}`);
  });
}

check();
