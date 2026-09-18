require('dotenv').config();

const {
  checkDatabaseConnection,
  closeDatabase,
  initializeDatabase,
} = require('./db');

async function main() {
  const checkOnly = process.argv.includes('--check');
  await checkDatabaseConnection();

  if (checkOnly) {
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
