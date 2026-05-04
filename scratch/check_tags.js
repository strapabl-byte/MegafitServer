const fs = require('fs');
const content = fs.readFileSync('c:\\Users\\Thatsme\\Documents\\MegaSolution\\megafit-dashboard3\\src\\pages\\Auralix.jsx', 'utf8');
const lines = content.split('\n');

let balance = 0;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const opens = (line.match(/<div(?![^>]*\/>)/g) || []).length;
  const closes = (line.match(/<\/div>/g) || []).length;
  
  balance += opens;
  balance -= closes;
  
  if (balance < 0) {
    console.log(`❌ Balance went negative at line ${i + 1}: ${line.trim()}`);
    // Reset balance to 0 to keep searching for more
    balance = 0;
  }
}
console.log('Final Balance:', balance);
