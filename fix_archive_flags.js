const db = require('better-sqlite3')('megafit_cache.db');

const res = db.prepare(`
  UPDATE members_cache 
  SET is_archive = 1 
  WHERE id LIKE 'odoo_%' 
     OR full_name IS NULL 
     OR length(trim(full_name)) <= 1
`).run();

console.log('Successfully marked as archive:', res.changes);

// Also delete members that are NOT archive but have no name (clean up test data)
const del = db.prepare(`
  DELETE FROM members_cache 
  WHERE is_archive = 0 
    AND (full_name IS NULL OR length(trim(full_name)) <= 1)
`).run();

console.log('Deleted nameless active members:', del.changes);
