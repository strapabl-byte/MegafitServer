
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

async function submitInscription(data) {
    const res = await fetch('http://localhost:4000/public/inscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    return res.json();
}

const user1 = {
    gymId: 'dokarat',
    commercial: 'MAROUANE',
    nom: 'EL AMRANI',
    prenom: 'Youssef',
    cin: 'BK123456',
    dateNaissance: '1995-05-15',
    telephone: '0661234567',
    email: 'youssef@example.com',
    subscriptionName: 'ANNUAL',
    subscriptionAmount: '3000',
    periodFrom: '2026-04-12',
    periodTo: '2027-04-12',
    memberSignature: 'data:image/png;base64,mock',
    acceptConditions: true,
    acceptDataProtection: true,
    totals: { registration: 0, subscription: 3000, insurance: 0, coaching: 0, total: 3000, paid: 3000, balance: 0 }
};

const user2 = {
    gymId: 'dokarat',
    commercial: 'MAROUANE',
    nom: 'BENNANI',
    prenom: 'Sarah',
    cin: 'CD789012',
    dateNaissance: '1998-09-20',
    telephone: '0667890123',
    email: 'sarah@example.com',
    subscriptionName: '6 MONTHS',
    subscriptionAmount: '1500',
    periodFrom: '2026-04-12',
    periodTo: '2026-10-12',
    memberSignature: 'data:image/png;base64,mock',
    acceptConditions: true,
    acceptDataProtection: true,
    totals: { registration: 300, subscription: 1500, insurance: 0, coaching: 0, total: 1800, paid: 500, balance: 1300 }
};

async function run() {
    console.log("Submitting User 1...");
    const r1 = await submitInscription(user1);
    console.log("User 1:", r1);

    console.log("Submitting User 2...");
    const r2 = await submitInscription(user2);
    console.log("User 2:", r2);
}

run();
