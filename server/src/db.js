// Capa unica de acceso a PostgreSQL (Supabase) e inicializacion del esquema del servidor.
// El proyecto usa exclusivamente Supabase: no existe ningun almacenamiento local de respaldo.
const fs = require('node:fs/promises');
const path = require('node:path');
const { Pool } = require('pg');

// Se valida al cargar para fallar con un mensaje claro si la cadena de conexion
// falta o sigue siendo el placeholder de .env.example, en vez de intentar
// conectarse a un host inexistente con un error poco entendible de pg.
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl || databaseUrl.includes('TU_PROJECT_REF') || databaseUrl.includes('YOUR_PROJECT_REF')) {
  throw new Error('DATABASE_URL must point to the Supabase PostgreSQL database (see server/.env.example)');
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
