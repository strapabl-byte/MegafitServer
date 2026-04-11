// import_day11.js — Imports April 11, 2026 registre data into MegafitServer
// Run with: node import_day11.js
// Requires local server running on http://localhost:4000

const API = "http://localhost:4000";
const TOKEN = "admin"; // mock admin token accepted by local server
const DATE  = "2026-04-11";
const GYM   = "dokarat";

const entries = [
  {
    contrat:    "-",
    commercial: "OUISSALE",
    nom:        "RHIZLANE SENHAJI",
    cin:        "CD511256",
    tel:        "663806032",
    prix:       "3600",
    tpe:        "3600",
    espece:     "0",
    virement:   "0",
    cheque:     "0",
    abonnement: "CARNET DENTREE JOURNALIERE 50",
    note_reste: "",
  },
  {
    contrat:    "14180",
    commercial: "OUISSALE",
    nom:        "NAJOUA EL YOUBI",
    cin:        "CD669583",
    tel:        "646643816",
    prix:       "2200",
    tpe:        "0",
    espece:     "2200",
    virement:   "0",
    cheque:     "0",
    abonnement: "3 MOIS",
    note_reste: "",
  },
  {
    contrat:    "14181",
    commercial: "HAJAR",
    nom:        "OUBOUKSIM HOUSSINE",
    cin:        "C647124",
    tel:        "665709042",
    prix:       "5900",
    tpe:        "0",
    espece:     "5900",
    virement:   "0",
    cheque:     "0",
    abonnement: "2 ANS S/V",
    note_reste: "",
  },
  {
    contrat:    "14183",
    commercial: "OUISSALE",
    nom:        "KHALOUTA YASMINE",
    cin:        "KIDS",
    tel:        "606142828",
    prix:       "3500",
    tpe:        "0",
    espece:     "0",
    virement:   "0",
    cheque:     "3500",
    abonnement: "1 AN PACK FAMILLE",
    note_reste: "CHEQUE ENCAISSABLE",
  },
  {
    contrat:    "14182",
    commercial: "HAJAR",
    nom:        "KHALOTA ISMAIL",
    cin:        "KIDS",
    tel:        "664497629",
    prix:       "3500",
    tpe:        "0",
    espece:     "3500",
    virement:   "0",
    cheque:     "0",
    abonnement: "1 AN PACK FAMILLE",
    note_reste: "",
  },
  {
    contrat:    "-",
    commercial: "HAJAR",
    nom:        "REDA JABER",
    cin:        "CD221864",
    tel:        "652760838",
    prix:       "200",
    tpe:        "0",
    espece:     "200",
    virement:   "0",
    cheque:     "0",
    abonnement: "COM/ DE MULTICLUB",
    note_reste: "",
  },
  {
    contrat:    "14184",
    commercial: "HAJAR",
    nom:        "HOURIA NADIR",
    cin:        "C414594",
    tel:        "668665252",
    prix:       "5900",
    tpe:        "5900",
    espece:     "0",
    virement:   "0",
    cheque:     "0",
    abonnement: "2 ANS S/V",
    note_reste: "",
  },
];

async function main() {
  console.log(`\n📋 Importing ${entries.length} entries for ${DATE} (gym: ${GYM})...\n`);

  let ok = 0;
  for (const entry of entries) {
    try {
      const res  = await fetch(`${API}/api/register/entry`, {
        method:  "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ date: DATE, gymId: GYM, ...entry }),
      });
      const data = await res.json();
      if (data.ok) {
        console.log(`  ✅ ${entry.nom.padEnd(25)} → id: ${data.id}`);
        ok++;
      } else {
        console.error(`  ❌ ${entry.nom}: ${JSON.stringify(data)}`);
      }
    } catch (err) {
      console.error(`  ❌ ${entry.nom}: ${err.message}`);
    }
  }

  console.log(`\n✨ Done — ${ok}/${entries.length} entries imported.\n`);

  // Quick sanity check
  const total = entries.reduce((s, e) => s + (parseInt(e.tpe)||0) + (parseInt(e.espece)||0) + (parseInt(e.virement)||0) + (parseInt(e.cheque)||0), 0);
  console.log(`💰 CA total: ${total.toLocaleString()} DH (expected 24 800 DH)\n`);
}

main().catch(console.error);
