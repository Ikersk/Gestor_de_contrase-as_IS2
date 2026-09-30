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

  // Detras de un proxy inverso (NGINX, load balancer) Express debe leer
  // X-Forwarded-For para que request.ip (clave del rate limiting) sea la IP
  // real del cliente y no la del proxy. Opt-in explicito via TRUST_PROXY
  // ("1" para un proxy, "loopback", "true"...); por defecto desactivado,
  // porque confiar en esa cabecera sin proxy permitiria evadir los limites
  // enviando una IP falsa.
  const trustProxySetting = process.env.TRUST_PROXY;
  if (trustProxySetting && trustProxySetting !== 'false') {
    const hops = Number(trustProxySetting);
    const parsed = trustProxySetting === 'true'
      ? true
      : (Number.isNaN(hops) ? trustProxySetting : hops);
    app.set('trust proxy', parsed);
  }

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

  // Respuestas 404 en JSON: si no, el manejador por defecto de Express devuelve
  // HTML y rompe el contrato JSON de la API.
  app.use((_request, response) => {
    response.status(404).json({ error: 'Not found' });
  });

  // Handler de errores global: body-parser (JSON roto o cuerpo > 2 MB) y
  // cualquier error interno caen aqui en vez del generador HTML por defecto,
  // que en desarrollo devolveria el stack trace como texto plano.
  app.use((error, _request, response, _next) => {
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) {
      console.error(error);
    }
    response.status(status).json({
      error: status >= 500 ? 'Internal server error' : 'Invalid request payload',
    });
  });

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
