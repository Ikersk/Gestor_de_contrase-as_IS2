const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');

const dataDirectory = path.resolve(__dirname, '../data');
const databasePath = path.join(dataDirectory, 'app.db');

fs.mkdirSync(dataDirectory, { recursive: true });

const database = new Database(databasePath);
database.pragma('foreign_keys = ON');
database.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email               TEXT UNIQUE NOT NULL,
    kdf_salt            TEXT NOT NULL,
    kdf_iterations      INTEGER NOT NULL,
    auth_hash_hashed    TEXT NOT NULL,
    wrapped_vault_key   TEXT NOT NULL,
    wrap_iv             TEXT NOT NULL,
    created_at          TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS vault_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    iv          TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at  TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

module.exports = { database, databasePath };
