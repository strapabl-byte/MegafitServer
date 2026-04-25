const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// The new Kids Planning
// Map to Day names: ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim']

const kidsCourses = [
  // Groupe A (5-9ans)
  { title: "KIDS A: Natation (5-9ans)", time: "14:30", days: ["Mer"] },
  { title: "KIDS A: Funfit (5-9ans)", time: "10:00", days: ["Sam"] },
  { title: "KIDS A: Natation (5-9ans)", time: "10:00", days: ["Dim"] },

  // Groupe B (10-14ans)
  { title: "KIDS B: Natation (10-14ans)", time: "15:30", days: ["Mer"] },
  { title: "KIDS B: Funfit (10-14ans)", time: "11:00", days: ["Sam"] },
  { title: "KIDS B: Natation (10-14ans)", time: "11:00", days: ["Dim"] },

  // Groupe C (Aqua nageurs)
  { title: "KIDS C: Natation (5-14ans)", time: "15:00", days: ["Ven"] },
  { title: "KIDS C: Funfit (5-8ans)", time: "10:00", days: ["Sam"] },
  { title: "KIDS C: Funfit (9-14ans)", time: "11:00", days: ["Sam"] },
  { title: "KIDS C: Natation (5-14ans)", time: "12:00", days: ["Dim"] },

  // Groupe D (Futurs Champions 5-14ans)
  { title: "KIDS D: Funfit (5-14ans)", time: "14:00", days: ["Sam"] },
  { title: "KIDS D: Natation (5-14ans)", time: "15:00", days: ["Sam"] },
  { title: "KIDS D: Natation (5-14ans)", time: "12:00", days: ["Dim"] },

  // Groupe E (Tout-Petits 3-4ans)
  { title: "KIDS E: Natation (3-4ans)", time: "14:30", days: ["Mer"] },
  { title: "KIDS E: Natation (3-4ans)", time: "10:00", days: ["Dim"] },
];

async function run() {
  console.log('Seeding Kids Schedule...');
  const coursesRef = db.collection('courses');
  
  const batch = db.batch();
  let count = 0;
  
  for (const c of kidsCourses) {
    const newDoc = coursesRef.doc();
    batch.set(newDoc, {
      title: c.title,
      coach: 'Equipe MegaFit Kids',
      time: c.time,
      capacity: 30, // Default kids capacity
      reserved: 0,
      days: c.days,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: 'Auto-Seeder-Kids'
    });
    count++;
  }
  
  await batch.commit();
  console.log(`✅ Successfully added ${count} Kids courses to the database!`);
  process.exit(0);
}

run().catch(console.error);
