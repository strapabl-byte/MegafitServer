const db = require('better-sqlite3')('./megafit_cache.db');
db.prepare(`INSERT INTO register_cache (id, gym_id, date, commercial, nom, tpe, espece, virement, cheque, prix, reste) 
            VALUES ('CORR_1504', 'dokarat', '2026-04-15', 'SYSTEM', 'CORRECTION CA', '100', '0', '0', '0', '100', '0')`).run();
console.log('✅ Correction finale de 100 DH appliquée.');
