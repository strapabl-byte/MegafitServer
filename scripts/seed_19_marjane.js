const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const entries = [
  {
    n_contrat: '14334',
    commercial: 'SARAH',
    name: 'KHAOULAJ ALLAL',
    cin: 'C216372',
    num_tel: '700025337',
    tpe: '0',
    espece: '0',
    virement: '0',
    cheque: '5900',
    av_comp: '24MOIS'
  },
  {
    n_contrat: '14335',
    commercial: 'SABER',
    name: 'KABILGHAZAL',
    cin: '-',
    num_tel: '336190518',
    tpe: '500',
    espece: '0',
    virement: '0',
    cheque: '0',
    av_comp: '7J'
  },
  {
    n_contrat: '14336',
    commercial: 'SABER',
    name: 'AGHOUTANE RAFIQUA',
    cin: 'Z260058',
    num_tel: '672663297',
    tpe: '5900',
    espece: '0',
    virement: '0',
    cheque: '0',
    av_comp: '24MOIS'
  },
  {
    n_contrat: '14244',
    commercial: 'AHLAM',
    name: 'EL HAROUI ZIYAD',
    cin: '-18',
    num_tel: '611754378',
    tpe: '0',
    espece: '0',
    virement: '0',
    cheque: '2750',
    av_comp: 'COMP 1 ANS KIDS'
  },
  {
    n_contrat: '14337',
    commercial: 'AHLAM',
    name: 'IDRISSI YOUSSEF',
    cin: 'CD921188',
    num_tel: '616831784',
    tpe: '0',
    espece: '5900',
    virement: '0',
    cheque: '0',
    av_comp: 'PROMO SAINT VALENTIN'
  }
];

const gymId = 'marjane';
const date = '2026-04-19';
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
