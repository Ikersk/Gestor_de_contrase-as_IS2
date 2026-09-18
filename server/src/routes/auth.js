// Rutas de identidad: reciben solo material derivado o cifrado, nunca la contrasena maestra.
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const express = require('express');

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUTH_HASH_BYTES = 32;
const SALT_BYTES = 16;
const WRAP_IV_BYTES = 12;
const WRAPPED_VAULT_KEY_BYTES = 32 + 16;
const JWT_COOKIE_NAME = 'session';
const DUMMY_AUTH_HASH = bcrypt.hashSync('dummy-auth-hash', 12);

/** Comprueba que un texto es base64 canonico y tiene el tamano criptografico esperado. */
function isBase64(value, expectedBytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    return false;
  }

  try {
    const decoded = Buffer.from(value, 'base64');
    return decoded.length === expectedBytes && decoded.toString('base64') === value;
  } catch (error) {
    return false;
  }
}

/** Normaliza el identificador de cuenta para que el email sea insensible a mayusculas. */
function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

/** Limita las iteraciones aceptadas para evitar configuraciones invalidas o abusivas. */
function isValidIterations(value) {
  return Number.isInteger(value) && value >= 100_000 && value <= 2_000_000;
}

/** Valida la forma del cuerpo que prepara el cliente durante el registro. */
function validateRegisterPayload(body) {
  return body
    && EMAIL_PATTERN.test(normalizeEmail(body.email))
    && isBase64(body.kdfSalt, SALT_BYTES)
    && isValidIterations(body.kdfIterations)
    && isBase64(body.authHash, AUTH_HASH_BYTES)
    && isBase64(body.wrappedVaultKey, WRAPPED_VAULT_KEY_BYTES)
    && isBase64(body.wrapIv, WRAP_IV_BYTES);
}

/** Valida la forma del cuerpo de login sin interpretar el Auth Hash. */
function validateLoginPayload(body) {
  return body
    && EMAIL_PATTERN.test(normalizeEmail(body.email))
    && isBase64(body.authHash, AUTH_HASH_BYTES);
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

  // POST /register: almacena el Auth Hash rehasheado y los blobs cifrados del cliente.
  router.post('/register', async (request, response, next) => {
    if (!validateRegisterPayload(request.body)) {
      return response.status(400).json({ error: 'Invalid registration payload' });
    }

    const email = normalizeEmail(request.body.email);
    try {
      const authHash = Buffer.from(request.body.authHash, 'base64');
      const authHashHashed = await bcrypt.hash(authHash.toString('base64'), 12);
      await dbPool.query(
        `INSERT INTO users
          (email, kdf_salt, kdf_iterations, auth_hash_hashed, wrapped_vault_key, wrap_iv)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [email, request.body.kdfSalt, request.body.kdfIterations, authHashHashed,
          request.body.wrappedVaultKey, request.body.wrapIv],
      );
      return response.status(201).end();
    } catch (error) {
      if (error.code === '23505') {
        return response.status(409).json({ error: 'Unable to register account' });
      }
      return next(error);
    }
  });

  // GET /salt?email=: devuelve el KDF salt real o uno falso si la cuenta no existe.
  router.get('/salt', saltLimiter, async (request, response, next) => {
    const email = normalizeEmail(request.query.email);
    if (!EMAIL_PATTERN.test(email)) {
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

  // POST /login: verifica el Auth Hash y devuelve la vault key envuelta junto con la sesion.
  router.post('/login', loginLimiter, async (request, response, next) => {
    if (!validateLoginPayload(request.body)) {
      return response.status(400).json({ error: 'Invalid login payload' });
    }

    const email = normalizeEmail(request.body.email);
    try {
      const result = await dbPool.query(
        `SELECT id, auth_hash_hashed, wrapped_vault_key, wrap_iv
         FROM users WHERE email = $1`,
        [email],
      );
      const user = result.rows[0];
      const hashToVerify = user?.auth_hash_hashed
        || DUMMY_AUTH_HASH;
      const valid = await bcrypt.compare(request.body.authHash, hashToVerify);

      if (!user || !valid) {
        return response.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ sub: String(user.id) }, getJwtSecret(), {
        algorithm: 'HS256',
        expiresIn: '8h',
      });
      response.cookie(JWT_COOKIE_NAME, token, getSessionCookieOptions());
      return response.json({ wrappedVaultKey: user.wrapped_vault_key, wrapIv: user.wrap_iv });
    } catch (error) {
      return next(error);
    }
  });

  // POST /logout: invalida la cookie en el navegador; la proteccion de la ruta llegara con requireAuth.
  router.post('/logout', (_request, response) => {
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