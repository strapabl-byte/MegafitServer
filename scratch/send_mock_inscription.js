
const API_URL = "http://localhost:4000";

async function sendMockInscription() {
    const mockData = {
        nom: "IDRISSI",
        prenom: "Amine",
        civility: "Monsieur",
        cin: "BK998877",
        dateNaissance: "1992-11-20",
        telephone: "0612345678",
        email: "amine.idrissi@test.com",
        gymId: "dokkarat",
        commercial: "MAROUANE",
        subscriptionName: "TRIMESTRIEL (3 MOIS)",
        periodFrom: "2026-04-12",
        periodTo: "2026-07-12",
        subscriptionAmount: "800",
        totals: {
            registration: 300,
            subscription: 800,
            insurance: 250,
            coaching: 0,
            total: 1350,
            paid: 1350,
            balance: 0
        },
        payments: {
            espece: "1350",
            carte: "0",
            cheque: "0",
            virement: "0"
        },
        memberSignature: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", // Mock 1x1 pixel
        acceptConditions: true
    };

    console.log("🚀 Sending mock inscription to API...");
    
    try {
        const res = await fetch(`${API_URL}/public/inscriptions`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(mockData)
        });

        const result = await res.json();
        if (result.ok) {
            console.log("✅ Success! Mock inscription created.");
            console.log("Document ID:", result.id);
            console.log("Status: PENDING (Waiting for approval)");
        } else {
            console.error("❌ API Error:", result.error);
        }
    } catch (err) {
        console.error("❌ Request failed:", err.message);
    }
}

sendMockInscription();
