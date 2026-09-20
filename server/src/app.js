require('dotenv').config();

// Punto de entrada de la API: configura Express y conecta los routers del servidor.
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { createAuthRouter } = require('./routes/auth');
const { createVaultRouter } = require('./routes/vault');
const {
  checkDatabaseConnection,
  closeDatabase,
  initializeDatabase,
  pool,
} = require('./db');

const port = Number(process.env.PORT || 3000);

/**
 * Construye la aplicacion Express.
 *
 * El pool se puede sustituir en tests para probar las rutas sin conectarse a
 * PostgreSQL. En produccion se utiliza el pool real exportado por db.js.
 */
function createApp({ dbPool = pool } = {}) {
  const app = express();

  const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  }));
  app.use(cors({
    origin: (requestOrigin, callback) => {
      callback(null, !requestOrigin || requestOrigin === frontendOrigin);
    },
    credentials: true,
  }));
  // Limita el cuerpo HTTP para que un blob cifrado grande no consuma memoria sin control.
  app.use(express.json({ limit: '2mb' }));

  // GET /health: confirma que la aplicacion y la conexion a PostgreSQL estan disponibles.
  app.get('/health', async (_request, response) => {
    try {
      await checkDatabaseConnection();
      response.status(200).json({ status: 'ok' });
    } catch (error) {
      response.status(503).json({ status: 'error' });
    }
  });

  // Todas las rutas de autenticacion quedan agrupadas bajo /api/auth.
  app.use('/api/auth', createAuthRouter({ dbPool }));
  // La boveda solo acepta peticiones con una sesion JWT valida.
  app.use('/api/vault', createVaultRouter({ dbPool }));

  return app;
}

const app = createApp();

if (require.main === module) {
  // El esquema se aplica antes de aceptar trafico para evitar arrancar con una DB incompleta.
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
module.exports.createApp = createApp;
