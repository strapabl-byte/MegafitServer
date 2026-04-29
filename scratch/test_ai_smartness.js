// Clean Test Script for AI Smartness
require('dotenv').config();
const path = require('path');
const lc = require('../localCache');
const analyticsFactory = require('../routes/analytics');

// Initialize router with dependencies
const router = analyticsFactory({ lc }); 
const { fuzzyMatchMembers, groqIdentify, detectStaff } = router;

async function runTests() {
  console.log('🚀 Starting Smart AI Identification Stress Test...\n');

  const tests = [
    { name: 'redamouss-comercial', gym: 'dokarat', desc: 'Staff Pattern (Synchronous)' },
    { name: 'Meskin Youns', gym: 'marjane', desc: 'Fuzzy Match + AI Disambiguation' },
    { name: 'Younes Meskine', gym: 'dokarat', desc: 'Multi-Gym Detection' },
    { name: 'Unknown User 123', gym: 'dokarat', desc: 'True Unknown' }
  ];

  for (const t of tests) {
    console.log(`Testing: "${t.name}" (${t.desc})`);
    
    // 1. Detect Staff
    const staff = detectStaff(t.name);
    if (staff) {
      console.log(`✅ [STAFF] Detected instantly: ${staff.displayName} (${staff.role} ${staff.emoji})`);
      console.log('--------------------------------------------------');
      continue;
    }

    // 2. Fuzzy Match
    const top = fuzzyMatchMembers(t.name, 5);
    console.log(`🔍 Top fuzzy matches found: ${top.length}`);
    top.slice(0, 2).forEach(m => console.log(`   - ${m.full_name} (${m.gym_id}) Score: ${m.score}%`));

    // 3. Identification logic
    const best = top[0];
    if (best && best.score >= 85) {
        if (best.gym_id === t.gym) {
            console.log(`✅ [MATCH] Confirmed: ${best.full_name}`);
        } else {
            console.log(`⚠️ [WRONG GYM] Member ${best.full_name} is at ${best.gym_id}`);
        }
    } else if (best && best.score >= 50) {
        console.log(`🤖 [GROQ] Ambiguous match (Score ${best.score}%). Sending to AI...`);
        const ai = await groqIdentify(t.name, null, top);
        if (ai) {
            console.log(`🤖 [AI PICK] ${ai.pick > 0 ? top[ai.pick-1].full_name : 'Unknown'}`);
            console.log(`🤖 [AI COMMENT] ${ai.comment}`);
        }
    } else {
        console.log(`❌ [UNKNOWN] No decent matches.`);
    }
    console.log('--------------------------------------------------\n');
  }
}

runTests().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
});
