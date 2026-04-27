const fs = require('fs');
const path = require('path');
const lc = require('../localCache');

const LOGS_DIR = 'c:/Users/Thatsme/Documents/MegaSolution/entrees';
const GYM_ID = 'dokarat';

async function run() {
  console.log(`Starting import of logs from ${LOGS_DIR} into SQLite...`);
  
  const files = fs.readdirSync(LOGS_DIR).filter(f => f.endsWith('.log'));
  console.log(`Found ${files.length} log files.`);

  let totalImported = 0;

  for (const file of files) {
    const filePath = path.join(LOGS_DIR, file);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    
    const entries = [];
    
    for (let line of lines) {
      line = line.trim();
      if (!line) continue;
      // Format: [2026-04-27 05:59:30] rachid konia | EntrAce | Visage ID
      const match = line.match(/^\[(.*?)\]\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*)$/);
      if (!match) {
        console.log("Failed to match:", line);
      }
      if (match) {
        const timestampRaw = match[1]; // e.g., 2026-04-27 05:59:30
        const timestamp = timestampRaw.replace(' ', 'T') + 'Z';
        const name = match[2].trim();
        const status = match[3].trim();
        const method = match[4].trim();
        
        entries.push({
          timestamp,
          name,
          status,
          method,
          isFace: method.toLowerCase().includes('visage'),
          id: `${GYM_ID}_${timestampRaw.replace(/\D/g, '')}_${name.replace(/\s/g, '_')}` // pseudo unique ID
        });
      }
    }

    if (entries.length > 0) {
      lc.upsertEntries(GYM_ID, entries);
      totalImported += entries.length;
      console.log(`✅ Imported ${entries.length} entries from ${file}`);
    }
  }

  console.log(`\n🎉 Import complete! Total entries inserted: ${totalImported}`);
  process.exit(0);
}

run().catch(console.error);
