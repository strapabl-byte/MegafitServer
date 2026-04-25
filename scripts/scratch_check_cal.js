const path = require('path');
const admin = require('firebase-admin');

const serviceAccount = require(path.join(__dirname, 'serviceAccount.json'));
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

async function checkCal() {
  const year = 2026;
  const gid = 'marjane';
  const prefix = `${gid}_${year}`;
  
  const snap = await db.collection('megafit_daily_register')
    .where(admin.firestore.FieldPath.documentId(), '>=', `${prefix}-01-01`)
    .where(admin.firestore.FieldPath.documentId(), '<=', `${prefix}-12-31`)
    .get();

  const calendarData = {};
  await Promise.all(snap.docs.map(async (parentDoc) => {
    const date = parentDoc.id.replace(`${gid}_`, '');
    const entriesSnap = await parentDoc.ref.collection('entries').get();
    let ca = 0;
    entriesSnap.docs.forEach(d => {
      const e = d.data();
      ca += (Number(e.tpe) || 0) + (Number(e.espece) || 0) + (Number(e.virement) || 0) + (Number(e.cheque) || 0);
    });
    if (ca > 0) calendarData[date] = ca;
  }));

  console.log("CALENDAR DATA DUMP:");
  console.log(JSON.stringify(calendarData, null, 2));
  process.exit(0);
}

checkCal().catch(console.error);
