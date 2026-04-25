const admin = require('firebase-admin');
const crypto = require('crypto');
const path = require('path');

const serviceAccount = require(path.join(__dirname, 'serviceAccount.json'));
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();


const gymId = 'marjane';
const date = '2026-04-23';

const newEntries = [
  { n_contrat: '-', commercial: 'AHLAM', nom_prenom: 'ESSEDDIK BENSEDIK', cin: 'CD98914', num_tele: '662501380', tpe: 0, espece: 5000, virement: 0, cheque: 0, av_comp: 'COMP COACHING 50' },
  { n_contrat: '14505', commercial: 'AHLAM', nom_prenom: 'ALAMI HASSANI AMINE', cin: 'CD387103', num_tele: '660027121', tpe: 1700, espece: 4200, virement: 0, cheque: 0, av_comp: 'PROMO SAINT VALENTIN' },
  { n_contrat: '14506', commercial: 'AHLAM', nom_prenom: 'MOUJAHID BOUCHRA', cin: '-', num_tele: '614994365', tpe: 500, espece: 500, virement: 0, cheque: 0, av_comp: '10 SEANCES CARNET JOURNALIER' },
  { n_contrat: '-', commercial: 'REDA', nom_prenom: 'AHMED SEBTI', cin: '-', num_tele: '662666001', tpe: 0, espece: 0, virement: 0, cheque: 3500, av_comp: 'COMP COACHING' },
  { n_contrat: '-', commercial: 'AHLAM', nom_prenom: 'FATIMA ZAHRA SAMINA', cin: '-', num_tele: '652549528', tpe: 2000, espece: 0, virement: 0, cheque: 0, av_comp: '10 SEANCES COACHING AVEC FIRDAWS' },
  { n_contrat: '14507', commercial: 'SARAH', nom_prenom: 'DOUIDA RANIA', cin: 'CB331091', num_tele: '651088579', tpe: 0, espece: 5900, virement: 0, cheque: 0, av_comp: 'PROMO SAINT VALENTIN' },
  { n_contrat: '14508', commercial: 'REDA', nom_prenom: 'ZINEB SEND', cin: 'CD972500', num_tele: '718329396', tpe: 1300, espece: 900, virement: 0, cheque: 0, av_comp: '3 MOIS' },
  { n_contrat: '14509', commercial: 'REDA', nom_prenom: 'MAJDA EL GHYAM', cin: 'D887631', num_tele: '684154008', tpe: 5900, espece: 0, virement: 0, cheque: 0, av_comp: 'PROMO SAINT VALENTIN' },
  { n_contrat: '150', commercial: 'REDA', nom_prenom: 'TEEJAN CAMARA', cin: 'A78091661', num_tele: '-', tpe: 0, espece: 200, virement: 0, cheque: 0, av_comp: 'ACCES JOURNALIER' }
];

async function insertMissing() {
  console.log(`Starting insertion into ${gymId} for ${date}...`);
  const colRef = db.collection('megafit_daily_register').doc(`${gymId}_${date}`).collection('entries');
  
  for (const entry of newEntries) {
    const prixTotal = entry.tpe + entry.espece + entry.virement + entry.cheque;
    
    const docData = {
      id: crypto.randomUUID(),
      date: date,
      gymId: gymId,
      nom: entry.nom_prenom,
      prenom: '',
      cin: entry.cin,
      telephone: entry.num_tele,
      commercial: entry.commercial,
      tpe: entry.tpe,
      espece: entry.espece,
      virement: entry.virement,
      cheque: entry.cheque,
      prix: prixTotal,
      reste: 0, // No reste column in screenshot, assuming fully paid or it's just a comp
      notes: entry.av_comp, // Storing AV/COMP in notes per request
      createdAt: new Date().toISOString()
    };

    await colRef.doc(docData.id).set(docData);
    console.log(`✅ Inserted ${entry.nom_prenom} -> Total: ${prixTotal} DH`);
  }
  
  console.log('Done inserting 9 entries into Firestore!');
  process.exit(0);
}

insertMissing().catch(console.error);
