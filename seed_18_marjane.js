const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const entries = [
  {
    n_contrat: '14330',
    commercial: 'REDA',
    name: 'EL MAAZOUZI ANAS',
    cin: 'CD514099',
    num_tel: '771607483',
    tpe: '0',
    espece: '3000',
    virement: '0',
    cheque: '0',
    av_comp: 'AV PROMO SAINT VALENTIN'
  },
  {
    n_contrat: '14078',
    commercial: 'SABER',
    name: 'EL MIDAOUI AMAL',
    cin: 'CD727434',
    num_tel: '657519741',
    tpe: '1900',
    espece: '0',
    virement: '0',
    cheque: '0',
    av_comp: 'COMP PROMO SAINT VALENTIN'
  },
  {
    n_contrat: '14331',
    commercial: 'MARWA',
    name: 'HIND CHAOUKI',
    cin: 'C718252',
    num_tel: '661251202',
    tpe: '0',
    espece: '0',
    virement: '6300',
    cheque: '0',
    av_comp: 'PROMO SAINT VALENTIN'
  },
  {
    n_contrat: '14332',
    commercial: 'AHLAM',
    name: 'AMRANI MASBAH',
    cin: 'CD658419',
    num_tel: '640278806',
    tpe: '0',
    espece: '2200',
    virement: '0',
    cheque: '0',
    av_comp: '3MOIS'
  },
  {
    n_contrat: '14333',
    commercial: 'SABER',
    name: 'ABABOU AYDAR',
    cin: 'CD714286',
    num_tel: '600981209',
    tpe: '0',
    espece: '2200',
    virement: '0',
    cheque: '0',
    av_comp: '3MOIS'
  }
];

const gymId = 'marjane';
const date = '2026-04-18';
const docId = `${gymId}_${date}`;

async function seed() {
  console.log(`Starting injection for ${gymId} on ${date}...`);
  try {
    for (const entry of entries) {
      await db.collection('megafit_daily_register').doc(docId).collection('entries').add({
        ...entry,
        location: gymId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: 'system_import'
      });
      console.log(`Inserted contract ${entry.n_contrat}`);
    }

    // Update parent document timestamp
    await db.collection('megafit_daily_register').doc(docId).set({
      gymId,
      date,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log('✅ Injection complete!');
    process.exit(0);
  } catch (e) {
    console.error('Error inserting records:', e);
    process.exit(1);
  }
}

seed();
