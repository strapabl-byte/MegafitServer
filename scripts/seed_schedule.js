const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccount.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// Helper to add random but deterministic reservations
const withRes = (name, props = {}) => ({
  name,
  capacity: 25,
  ...props
});

const SCHEDULE = {
  '07h00': [
    withRes('BOXE'),
    withRes('C.A.F'),
    withRes('RENFORCEMENT', { dark: true }),
    withRes('SPINNING'),
    withRes('GRIT'),
    { name: 'OUVERTURE A 08H00', span: 2, banner: true },
    { covered: true }
  ],
  '08h00': [
    withRes('AQUA FIT'),
    withRes('STRETCHING'),
    withRes('AQUA DYNAMIQUE'),
    withRes('Extrem\nABBOS', { multi: true }),
    withRes('AQUA FIT'),
    null,
    null,
  ],
  '09h00': [
    withRes('CARDIO ET ACCOMPAGNEMENT', { span: 3, capacity: 50, reserved: 38 }),
    { covered: true },
    { covered: true },
    withRes('CARDIO\nTRAINING', { multi: true }),
    null,
    null,
    null,
  ],
  '10h00': [
    withRes('Extrem\nABBOS', { multi: true }),
    withRes('BOXE'),
    withRes('TABATA'),
    null,
    withRes('Spécial\nABBOS', { multi: true }),
    null,
    null,
  ],
  '11h00': [
    withRes('CARDIO\nTRAINING', { multi: true }),
    withRes('SPINNING'),
    withRes('MEGA AQUA'),
    withRes('BOXE'),
    withRes('AQUA GYM'),
    withRes('MEGA TRX', { accent: true }),
    withRes('BOXE'),
  ],
  '12h00': [
    withRes('AQUA GYM'),
    withRes('LesMills\nBODYPUMP', { multi: true }),
    withRes('SPINNING'),
    withRes('YOGA'),
    null,
    withRes('YOGA'),
    withRes('PILATES'),
  ],
  '17h30': [
    withRes('AERO BOXE\nLesMills RPM', { multi: true }),
    withRes('SWISS BALL\nBOXE', { multi: true }),
    withRes('BODY BARRE\nCROSS fit', { multi: true }),
    withRes('GRIT\nMUAY-THAI', { multi: true }),
    withRes('AQUA DYNAMIQUE\nBODY BARRE', { multi: true }),
    null,
    null,
  ],
  '18h30': [
    withRes('LesMills BODYPUMP\nSPINNING\nAQUA DYNAMIQUE', { multi: true }),
    withRes('CROSS fit\nMEGA TRX\nLesMills RPM', { multi: true }),
    withRes('STEP CARDIO\nAQUA FIT\nBOXE', { multi: true }),
    withRes('HIT CARDIO\nLesMills RPM\nCIRCUIT', { multi: true }),
    withRes('LesMills RPM\nAQUA GYM\nHIT WORKOUT', { multi: true }),
    withRes('Spécial\nABBOS', { multi: true }),
    withRes('LesMills\nRPM', { multi: true }),
  ],
  '19h30': [
    withRes('LesMills BODYATTACK\nLesMills RPM\nAQUA FUSION', { multi: true }),
    withRes('SPINNING\nLesMills BODYCOMBAT\nCIRCUIT', { multi: true }),
    withRes('CIRCUIT TRAINING\nAQUA GYM\nLesMills BODYPUMP', { multi: true }),
    withRes('LesMills BODYCOMBAT\nLesMills RPM\nSPINNING', { multi: true }),
    withRes('SPINNING\nAQUA POWER\nLesMills BODYPUMP', { multi: true }),
    withRes('LesMills\nBODYPUMP', { multi: true }),
    withRes('Extrem\nABBOS', { multi: true }),
  ],
  '20h30': [
    withRes('Spécial ABBOS\nBOXE', { multi: true }),
    withRes('BOXE\nYOGA STRETCH', { multi: true }),
    withRes('AQUA DYNAMIQUE\nLesMills RPM', { multi: true }),
    withRes('BOXE\nLesMills BODYPUMP', { multi: true }),
    withRes('YOGA\nAQUA GYM', { multi: true }),
    null,
    null,
  ],
  '21h30': [
    withRes('PILATES'),
    withRes('LesMills\nRPM', { multi: true }),
    withRes('AQUA FUSION'),
    withRes('MEGA TRX', { accent: true }),
    withRes('BOXE'),
    { name: 'FERMETURE A 22H00', span: 2, banner: true },
    { covered: true }
  ],
};

const WEEKDAYS = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'];

async function run() {
  console.log('Fetching old courses...');
  const coursesRef = db.collection('courses');
  const oldSnap = await coursesRef.get();
  
  if (!oldSnap.empty) {
    console.log(`Deleting ${oldSnap.docs.length} old courses...`);
    const batch = db.batch();
    oldSnap.docs.forEach(doc => {
      batch.delete(doc.ref);
    });
    await batch.commit();
  }
  
  console.log('Old courses deleted. Building new courses map...');
  
  // Map to hold unique classes: key -> { title, time, capacity, days: Set }
  // We'll set coach to "MegaFit" as default since they aren't explicitly bound yet
  const classMap = {};
  
  for (const time of Object.keys(SCHEDULE)) {
    const slots = SCHEDULE[time];
    let currentSpanName = null;
    let spanCount = 0;
    
    for (let i = 0; i < 7; i++) {
        const slot = slots[i];
        
        let targetName = null;
        let targetCapacity = 25;
        
        if (slot && slot.banner) continue; // Skip banners
        
        if (slot && slot.name && !slot.covered) {
             targetName = slot.name.replace(/\n/g, ' '); // Clean newlines
             targetCapacity = slot.capacity || 25;
             
             if (slot.span) {
                 spanCount = slot.span;
                 currentSpanName = { name: targetName, cap: targetCapacity };
             }
        } else if (slot && slot.covered && spanCount > 1) {
             targetName = currentSpanName.name;
             targetCapacity = currentSpanName.cap;
        } else if (!slot && spanCount > 1) {
             spanCount--;
        }

        if (spanCount > 0) spanCount--;
        
        if (targetName) {
            const key = `${targetName}-${time}`;
            if (!classMap[key]) {
                 classMap[key] = {
                     title: targetName,
                     coach: 'Equipe MegaFit',
                     time: time.replace('h', ':'),
                     capacity: targetCapacity,
                     days: new Set()
                 };
            }
            classMap[key].days.add(WEEKDAYS[i]);
        }
    }
  }

  console.log(`Prepared ${Object.keys(classMap).length} distinct courses. Seeding to Database...`);
  
  let i = 0;
  for (const key of Object.keys(classMap)) {
      const c = classMap[key];
      await coursesRef.add({
          title: c.title,
          coach: c.coach,
          time: c.time,
          capacity: c.capacity,
          days: Array.from(c.days),
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          createdBy: 'Auto-Seeder'
      });
      i++;
  }
  
  console.log(`✅ Synchronization complete. Added ${i} new courses exactly matching the weekly schedule.`);
  process.exit(0);
}

run().catch(console.error);
