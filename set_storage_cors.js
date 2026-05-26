/**
 * set_storage_cors.js
 * Configures Firebase Storage CORS to allow megafitauth.web.app to fetch images.
 * Run once: node set_storage_cors.js
 */
const { Storage } = require('@google-cloud/storage');
const path = require('path');

const BUCKET_NAME = 'mega-b891d.firebasestorage.app';
const SERVICE_ACCOUNT = path.join(__dirname, 'serviceAccount.json');

const CORS_CONFIG = [
  {
    origin: [
      'https://megafitauth.web.app',
      'https://megafitauth.firebaseapp.com',
      'http://localhost:5173',
      'http://localhost:3000',
    ],
    method: ['GET', 'HEAD'],
    responseHeader: ['Content-Type', 'Content-Length'],
    maxAgeSeconds: 3600,
  },
];

async function main() {
  const storage = new Storage({ keyFilename: SERVICE_ACCOUNT });
  const bucket = storage.bucket(BUCKET_NAME);
  await bucket.setCorsConfiguration(CORS_CONFIG);
  console.log('✅ CORS configured on bucket:', BUCKET_NAME);
  // Verify
  const [meta] = await bucket.getMetadata();
  console.log('Current CORS:', JSON.stringify(meta.cors, null, 2));
}

main().catch(err => { console.error('❌ Error:', err.message); process.exit(1); });
