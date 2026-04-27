const fs = require('fs');
const readline = require('readline');

async function analyzeCSV() {
  const filePath = 'c:\\Users\\Thatsme\\Documents\\MegaSolution\\odoo\\members_fes_doukkarate.csv';
  
  const fileStream = fs.createReadStream(filePath);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  let header = [];
  let count = 0;
  let lineNum = 0;
  
  // Date parsing helper for format like "DD/MM/YYYY" or "YYYY-MM-DD"
  // Assuming the Odoo CSV might have standard dates
  function parseDate(dStr) {
    if (!dStr) return null;
    const s = dStr.trim().replace(/"/g, '');
    if (!s) return null;
    
    // Format YYYY-MM-DD
    if (s.match(/^\d{4}-\d{2}-\d{2}/)) {
      return new Date(s);
    }
    
    // Format DD/MM/YYYY
    const parts = s.split(/[\/\-]/);
    if (parts.length >= 3) {
      if (parts[2].length === 4) { // DD/MM/YYYY
        return new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
      }
    }
    
    const d = new Date(s);
    return isNaN(d) ? null : d;
  }

  const outFilePath = 'c:\\Users\\Thatsme\\Documents\\MegaSolution\\odoo\\eligible_members_doukkarate.csv';
  const outStream = fs.createWriteStream(outFilePath);

  for await (const line of rl) {
    lineNum++;
    
    // Very basic CSV parser that handles quotes
    const regex = /(".*?"|[^",\s]+)(?=\s*,|\s*$)/g;
    let match;
    const values = [];
    let start = 0;
    let inQuotes = false;
    let val = '';
    
    for (let i = 0; i < line.length; i++) {
        if (line[i] === '"') inQuotes = !inQuotes;
        else if (line[i] === ',' && !inQuotes) {
            values.push(val);
            val = '';
        } else {
            val += line[i];
        }
    }
    values.push(val);

    if (lineNum === 1) {
      header = values.map(v => v.replace(/"/g, '').trim().toLowerCase());
      outStream.write(line + '\n'); // Write header to output
      console.log('Headers:', header.join(', '));
      continue;
    }

    let enrollDateStr = '';
    let expireDateStr = '';
    
    for (let i = 0; i < header.length; i++) {
      const h = header[i];
      const v = values[i] || '';
      
      if (h.includes('create') || h.includes('inscription') || h === 'date') {
        if (!enrollDateStr) enrollDateStr = v;
      }
      if (h.includes('start')) {
        enrollDateStr = v;
      }
      if (h.includes('end') || h.includes('expir') || h.includes('fin') || h.includes('stop')) {
        expireDateStr = v;
      }
    }

    const enrollDate = parseDate(enrollDateStr);
    const expireDate = parseDate(expireDateStr);

    if (enrollDate && expireDate) {
      const limitEnroll = new Date('2025-10-31T00:00:00Z');
      const limitExpireStart = new Date('2026-01-01T00:00:00Z');
      const limitExpireEnd = new Date('2026-05-01T23:59:59Z');
      
      if (enrollDate <= limitEnroll) {
        const now = new Date(); 
        const stillRunning = expireDate > now;
        const finishedInWindow = expireDate >= limitExpireStart && expireDate <= limitExpireEnd;
        
        if (stillRunning || finishedInWindow) {
          count++;
          outStream.write(line + '\n'); // Write eligible row to output
        }
      }
    }
  }

  outStream.end();
  console.log(`\nTotal eligible members found: ${count}`);
  console.log(`List saved to: ${outFilePath}`);
}

analyzeCSV().catch(console.error);
