require('dotenv').config();

const express = require('express');
const {
  checkDatabaseConnection,
  closeDatabase,
  initializeDatabase,
} = require('./db');

const app = express();
const port = Number(process.env.PORT || 3000);

app.use(express.json());

app.get('/health', async (_request, response) => {
  try {
    await checkDatabaseConnection();
    response.status(200).json({ status: 'ok' });
  } catch (error) {
    response.status(503).json({ status: 'error' });
  }
});

if (require.main === module) {
  initializeDatabase()
    .then(() => {
      app.listen(port, () => {
        console.log(`Server listening on http://localhost:${port}`);
      });
    })
    .catch((error) => {
      console.error('Server startup failed:', error.message);
      process.exitCode = 1;
    });
}

process.on('SIGINT', () => {
  closeDatabase().finally(() => process.exit(0));
});

process.on('SIGTERM', () => {
  closeDatabase().finally(() => process.exit(0));
});

module.exports = app;
