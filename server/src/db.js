const fs = require('node:fs/promises');
const path = require('node:path');
const { Pool } = require('pg');

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error('DATABASE_URL must be set before starting the server');
}

const useSsl = process.env.DB_SSL !== 'false';
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: useSsl
    ? {
        rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'true',
      }
    : false,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function checkDatabaseConnection() {
  await pool.query('SELECT 1');
}

async function initializeDatabase() {
  const schemaPath = path.resolve(__dirname, '../sql/001_initial_schema.sql');
  const schema = await fs.readFile(schemaPath, 'utf8');
  await pool.query(schema);
}

async function closeDatabase() {
  await pool.end();
}

module.exports = {
  pool,
  checkDatabaseConnection,
  closeDatabase,
  initializeDatabase,
};
