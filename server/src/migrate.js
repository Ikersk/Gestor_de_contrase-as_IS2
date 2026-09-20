require('dotenv').config();

// CLI de mantenimiento: comprueba la conexion o aplica el esquema inicial.
const {
  checkDatabaseConnection,
  closeDatabase,
  initializeDatabase,
} = require('./db');

async function main() {
  const checkOnly = process.argv.includes('--check');
  await checkDatabaseConnection();

  if (checkOnly) {
    // --check no modifica la base de datos; solo sirve para diagnosticar conectividad.
    console.log('PostgreSQL connection is available.');
    return;
  }

  await initializeDatabase();
  console.log('PostgreSQL schema is up to date.');
}

main()
  .catch((error) => {
    console.error('Database operation failed:', error.message);
    process.exitCode = 1;
  })
  .finally(closeDatabase);
