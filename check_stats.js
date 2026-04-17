const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();

async function debugKPIs(gymId = 'dokarat') {
    const now = new Date();
    // Start of current month
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const tsStart = admin.firestore.Timestamp.fromDate(startOfMonth);

    console.log(`Debug KPIs for ${gymId} starting from ${startOfMonth.toISOString()}`);

    // 1. Check Members collection
    const membersSnap = await db.collection('members')
        .where('location', '==', gymId)
        .where('createdAt', '>=', tsStart)
        .get();
    console.log(`Members collection count: ${membersSnap.size}`);

    // 2. Check Payments collection
    const paymentsSnap = await db.collection('payments')
        .where('gymId', '==', gymId)
        .where('createdAt', '>=', tsStart)
        .get();
    
    let paymentTotal = 0;
    paymentsSnap.forEach(doc => {
        paymentTotal += (Number(doc.data().amount) || 0);
    });
    console.log(`Payments collection total: ${paymentTotal} DH (${paymentsSnap.size} payments)`);

    // 3. Check Daily Register
    // We need to fetch docs with ID like gymId_YYYY-MM-DD
    // Better iterate over the collection
    const registerSnap = await db.collection('megafit_daily_register')
        .where('gymId', '==', gymId)
        .where('date', '>=', startOfMonth.toISOString().split('T')[0])
        .get();
    
    let registerTotal = 0;
    let registerEntriesCount = 0;
    
    for (const dayDoc of registerSnap.docs) {
        const entriesSnap = await dayDoc.ref.collection('entries').get();
        registerEntriesCount += entriesSnap.size;
        entriesSnap.forEach(entry => {
            const data = entry.data();
            // Income in register is sum of modes
            const rowTotal = (Number(data.tpe)||0) + (Number(data.espece)||0) + (Number(data.virement)||0) + (Number(data.cheque)||0);
            registerTotal += rowTotal;
        });
    }
    console.log(`Register total: ${registerTotal} DH (${registerEntriesCount} entries across ${registerSnap.size} days)`);
}

debugKPIs().catch(console.error);
