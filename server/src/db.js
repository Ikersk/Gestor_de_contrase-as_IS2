// Capa unica de acceso a PostgreSQL y de inicializacion del esquema del servidor.
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

/** Comprueba que el pool puede ejecutar consultas contra PostgreSQL. */
async function checkDatabaseConnection() {
  await pool.query('SELECT 1');
}

/** Lee y ejecuta las migraciones SQL idempotentes del proyecto en orden. */
async function initializeDatabase() {
  const sqlDirectory = path.resolve(__dirname, '../sql');
  const migrationFiles = (await fs.readdir(sqlDirectory))
    .filter((file) => /^\d+_.+\.sql$/.test(file))
    .sort();
  for (const migrationFile of migrationFiles) {
    const migration = await fs.readFile(path.join(sqlDirectory, migrationFile), 'utf8');
    await pool.query(migration);
  }
}

/** Cierra el pool para liberar conexiones durante el apagado del proceso. */
async function closeDatabase() {
  await pool.end();
}

module.exports = {
  pool,
  checkDatabaseConnection,
  closeDatabase,
  initializeDatabase,
};
