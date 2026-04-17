const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();

async function testKPIReconciliation(gymId = 'dokarat') {
    const now = new Date(); // Local: April 16 approx 04:30
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const tsMonth = admin.firestore.Timestamp.fromDate(monthStart);

    console.log(`Testing Reconciliation for ${gymId} from ${monthStart.toISOString()} to ${now.toISOString()}`);

    const fetchRegisterData = async (ts) => {
        const start = new Date(ts.toMillis());
        const entries = [];
        const gymIds = gymId === 'all' ? ['dokarat', 'marjane', 'casa1', 'casa2'] : [gymId];
        
        const dayCount = Math.ceil((now - start) / (1000 * 60 * 60 * 24)) + 1;
        const docRefs = [];
        
        console.log(`Calculating for ${dayCount} days...`);

        for (let i = 0; i < dayCount; i++) {
            const d = new Date(start);
            d.setDate(start.getDate() + i);
            if (d > now) break;
            const dateStr = d.toISOString().split('T')[0];
            gymIds.forEach(gid => {
                const docId = `${gid}_${dateStr}`;
                // console.log(`Queuing: ${docId}`);
                docRefs.push(db.collection("megafit_daily_register").doc(docId).collection("entries"));
            });
        }

        const snapshots = await Promise.all(docRefs.map(ref => ref.get()));
        console.log(`Fetched ${snapshots.length} daily collections.`);

        snapshots.forEach((snap, idx) => {
            // console.log(`Day ${idx}: ${snap.size} entries`);
            snap.forEach(doc => {
                const e = doc.data();
                if (e.source !== 'inscription_auto') {
                    entries.push(e);
                }
            });
        });
        return entries;
    };

    const manualEntriesMonth = await fetchRegisterData(tsMonth);
    console.log(`Total Manual Entries Found: ${manualEntriesMonth.length}`);

    const sumManualIncome = (entries) => entries.reduce((sum, e) => {
        const total = (Number(e.tpe)||0) + (Number(e.espece)||0) + (Number(e.virement)||0) + (Number(e.cheque)||0);
        return sum + total;
    }, 0);

    const totalIncome = sumManualIncome(manualEntriesMonth);
    console.log(`Total Income from Register: ${totalIncome} DH`);
    
    if (totalIncome < 400000) {
        console.error(`❌ DISCREPANCY DETECTED: Expected ~487k, got ${totalIncome}`);
        // Detailed check of first day
        const day1Id = `${gymId}_2026-04-01`;
        const day1Snap = await db.collection("megafit_daily_register").doc(day1Id).collection("entries").get();
        console.log(`Direct check of ${day1Id}: ${day1Snap.size} entries.`);
    } else {
        console.log(`✅ TOTAL MATCHES EXPECTATIONS: ${totalIncome} DH`);
    }
}

testKPIReconciliation().catch(console.error);
