// Rutas de identidad: reciben solo material derivado o cifrado, nunca la contrasena maestra.
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const express = require('express');
const { requireAuth } = require('../middleware/requireAuth');
const {
  changeMasterPasswordSchema,
  loginSchema,
  parsePayload,
  registerSchema,
} = require('../validation');

const SALT_BYTES = 16;
const JWT_COOKIE_NAME = 'session';
const DUMMY_AUTH_HASH = bcrypt.hashSync('dummy-auth-hash', 12);

/** Normaliza el identificador de cuenta para que el email sea insensible a mayusculas. */
function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

/** Obtiene el secreto del servidor usado para firmar JWT y salts falsos. */
function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set and contain at least 32 characters');
  }
  return secret;
}

/** Define las propiedades de seguridad y la duracion de la cookie de sesion. */
function getSessionCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE !== 'false',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  };
}

async function withTransaction(dbPool, operation) {
  const client = await dbPool.connect();
  try {
    await client.query('BEGIN');
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/** Genera un salt determinista para ocultar si un email existe en la base de datos. */
function createFakeSalt(email) {
  return crypto.createHmac('sha256', getJwtSecret()).update(email).digest().subarray(0, SALT_BYTES);
}

/**
 * Crea el router de autenticacion y sus limitadores independientes.
 *
 * El pool se inyecta para mantener las consultas parametrizadas en produccion
 * y poder probar el contrato HTTP con un almacenamiento controlado.
 */
function createAuthRouter({ dbPool }) {
  const router = express.Router();
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Try again later.' },
  });
  const saltLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many salt requests. Try again later.' },
  });

  // Valida, rehashea y persiste solo el material derivado que prepara el cliente.
  // POST /register: almacena el Auth Hash rehasheado y los blobs cifrados del cliente.
  router.post('/register', async (request, response, next) => {
    const payload = parsePayload(registerSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid registration payload' });
    }

    const email = payload.email;
    try {
      const authHash = Buffer.from(payload.authHash, 'base64');
      const authHashHashed = await bcrypt.hash(authHash.toString('base64'), 12);
      await dbPool.query(
        `INSERT INTO users
          (email, kdf_salt, kdf_iterations, auth_hash_hashed, wrapped_vault_key, wrap_iv)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [email, payload.kdfSalt, payload.kdfIterations, authHashHashed,
          payload.wrappedVaultKey, payload.wrapIv],
      );
      return response.status(201).end();
    } catch (error) {
      if (error.code === '23505') {
        return response.status(409).json({ error: 'Unable to register account' });
      }
      return next(error);
    }
  });

  // Devuelve siempre una respuesta estructuralmente válida para dificultar la enumeración de usuarios.
  // GET /salt?email=: devuelve el KDF salt real o uno falso si la cuenta no existe.
  router.get('/salt', saltLimiter, async (request, response, next) => {
    const email = normalizeEmail(request.query.email);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return response.status(400).json({ error: 'Invalid email' });
    }

    try {
      const result = await dbPool.query(
        'SELECT kdf_salt, kdf_iterations FROM users WHERE email = $1',
        [email],
      );
      const user = result.rows[0];
      return response.json({
        kdfSalt: user ? user.kdf_salt : createFakeSalt(email).toString('base64'),
        kdfIterations: user ? user.kdf_iterations : 600_000,
      });
    } catch (error) {
      return next(error);
    }
  });

  // Compara incluso contra un hash ficticio para que los emails inexistentes no tengan un camino barato.
  // POST /login: verifica el Auth Hash y devuelve la vault key envuelta junto con la sesion.
  router.post('/login', loginLimiter, async (request, response, next) => {
    const payload = parsePayload(loginSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid login payload' });
    }

    const email = payload.email;
    try {
      const result = await dbPool.query(
        `SELECT id, auth_hash_hashed, wrapped_vault_key, wrap_iv, session_version
         FROM users WHERE email = $1`,
        [email],
      );
      const user = result.rows[0];
      const hashToVerify = user?.auth_hash_hashed
        || DUMMY_AUTH_HASH;
      const valid = await bcrypt.compare(payload.authHash, hashToVerify);

      if (!user || !valid) {
        return response.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ sub: String(user.id), sv: user.session_version }, getJwtSecret(), {
        algorithm: 'HS256',
        expiresIn: '8h',
      });
      response.cookie(JWT_COOKIE_NAME, token, getSessionCookieOptions());
      return response.json({ wrappedVaultKey: user.wrapped_vault_key, wrapIv: user.wrap_iv });
    } catch (error) {
      return next(error);
    }
  });

  const changePasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many password change attempts. Try again later.' },
  });

  // Cambia los derivados y el envoltorio de la misma Vault Key dentro de una transaccion.
  router.post('/change-password', changePasswordLimiter, requireAuth({ dbPool }), async (request, response, next) => {
    const payload = parsePayload(changeMasterPasswordSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid password change payload' });
    }

    try {
      await withTransaction(dbPool, async (client) => {
        const result = await client.query(
          'SELECT auth_hash_hashed FROM users WHERE id = $1 FOR UPDATE',
          [request.user.id],
        );
        const user = result.rows[0];
        const valid = user && await bcrypt.compare(payload.currentAuthHash, user.auth_hash_hashed);
        if (!valid) {
          const error = new Error('Invalid current credentials');
          error.statusCode = 401;
          throw error;
        }

        const newAuthHashHashed = await bcrypt.hash(payload.authHash, 12);
        await client.query(
          `UPDATE users
           SET kdf_salt = $1, kdf_iterations = $2, auth_hash_hashed = $3,
               wrapped_vault_key = $4, wrap_iv = $5, session_version = session_version + 1
           WHERE id = $6`,
          [payload.kdfSalt, payload.kdfIterations, newAuthHashHashed,
            payload.wrappedVaultKey, payload.wrapIv, request.user.id],
        );
      });

      response.clearCookie(JWT_COOKIE_NAME, getSessionCookieOptions());
      return response.sendStatus(204);
    } catch (error) {
      if (error.statusCode === 401) return response.status(401).json({ error: 'Invalid credentials' });
      return next(error);
    }
  });

  // POST /logout: invalida la cookie en el navegador; la proteccion de la ruta llegara con requireAuth.
  router.post('/logout', requireAuth({ dbPool }), (_request, response) => {
    response.clearCookie(JWT_COOKIE_NAME, getSessionCookieOptions());
    response.sendStatus(204);
  });

  // Evita exponer detalles de base de datos o criptografia en respuestas de error.
  router.use((error, _request, response, _next) => {
    response.status(500).json({ error: 'Internal server error' });
  });

  return router;
}

module.exports = { createAuthRouter };