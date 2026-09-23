// Adaptador de base de datos local SQLite compatible con la interfaz pg.Pool
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const dataDir = path.resolve(__dirname, '../data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'vault.db');
const db = new DatabaseSync(dbPath);

// Habilitar integridad de llaves foráneas y modo WAL para mejor concurrencia
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

function adaptSql(sql) {
  let s = sql.trim();
  // Eliminar cláusula FOR UPDATE no soportada en SQLite
  s = s.replace(/\s+FOR\s+UPDATE/gi, '');
  // Reemplazar marcadores posicionales PostgreSQL ($1, $2, ...) por ?
  s = s.replace(/\$\d+/g, '?');
  return s;
}

const localPool = {
  async query(sql, params = []) {
    const rawSql = sql.trim();

    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(rawSql)) {
      try {
        db.exec(rawSql);
      } catch (err) {
        // Ignorar si no hay transacción activa en rollback
        if (!rawSql.includes('ROLLBACK')) throw err;
      }
      return { rows: [], rowCount: 0 };
    }

    const adaptedSql = adaptSql(rawSql);

    try {
      const stmt = db.prepare(adaptedSql);

      // Si la consulta contiene RETURNING o es un SELECT, devuelve filas
      if (/RETURNING/i.test(adaptedSql) || /^SELECT\b/i.test(adaptedSql)) {
        const rows = stmt.all(...params);
        return {
          rows: rows.map((row) => ({ ...row })),
          rowCount: rows.length,
        };
      }

      // Para INSERT, UPDATE, DELETE sin RETURNING
      const result = stmt.run(...params);
      return {
        rows: [],
        rowCount: Number(result.changes),
      };
    } catch (error) {
      if (
        error.message.includes('UNIQUE constraint failed') ||
        error.message.includes('SQLITE_CONSTRAINT_UNIQUE')
      ) {
        error.code = '23505'; // Código de PostgreSQL para violación de restricción única
      }
      throw error;
    }
  },

  async connect() {
    return {
      query: (sql, params) => localPool.query(sql, params),
      release: () => {},
    };
  },

  async end() {
    db.close();
  },
};

async function checkDatabaseConnection() {
  await localPool.query('SELECT 1');
}

async function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      email             TEXT NOT NULL UNIQUE,
      kdf_salt          TEXT NOT NULL,
      kdf_iterations    INTEGER NOT NULL,
      auth_hash_hashed  TEXT NOT NULL,
      wrapped_vault_key TEXT NOT NULL,
      wrap_iv           TEXT NOT NULL,
      session_version   INTEGER NOT NULL DEFAULT 0,
      created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS vault_items (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      iv         TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS vault_items_user_id_idx
      ON vault_items (user_id);
  `);
}

async function closeDatabase() {
  await localPool.end();
}

module.exports = {
  pool: localPool,
  checkDatabaseConnection,
  initializeDatabase,
  closeDatabase,
};
