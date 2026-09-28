// Rutas de identidad: reciben solo material derivado o cifrado, nunca la contrasena maestra.
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const express = require('express');
const { requireAuth } = require('../middleware/requireAuth');
const { requireMfaPending } = require('../middleware/requireMfaPending');
const {
  buildOtpauthUri,
  decryptSecret,
  encryptSecret,
  generateTotpSecret,
  verifyTotpCode,
} = require('../totp-secret');
const {
  findMatchingBackupCode,
  generateBackupCodes,
  hashBackupCode,
} = require('../mfa-backup-codes');
const {
  changeMasterPasswordSchema,
  deleteAccountSchema,
  loginSchema,
  mfaCodeSchema,
  parsePayload,
  registerSchema,
} = require('../validation');

const SALT_BYTES = 16;
const JWT_COOKIE_NAME = 'session';
const MFA_COOKIE_NAME = 'mfa';
const MFA_COOKIE_TTL_MS = 5 * 60 * 1000; // El reto intermedio caduca rapido a proposito.
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

/** Opciones del reto MFA intermadiario: misma politica de seguridad, pero efimero. */
function getMfaCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE !== 'false',
    sameSite: 'strict',
    maxAge: MFA_COOKIE_TTL_MS,
    path: '/',
  };
}

/** Firma la cookie de sesion definitiva; se reutiliza tras verificar el segundo factor. */
function signSessionCookie(response, user) {
  const token = jwt.sign({ sub: String(user.id), sv: user.session_version }, getJwtSecret(), {
    algorithm: 'HS256',
    expiresIn: '8h',
  });
  response.cookie(JWT_COOKIE_NAME, token, getSessionCookieOptions());
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
 * Traduce los fallos conocidos del flujo MFA a respuestas HTTP concretas sin
 * filtrar el motivo interno a un cliente no autorizado.
 */
function respondMfaError(error, response, next) {
  if (Number.isInteger(error.statusCode) && error.publicMessage) {
    return response.status(error.statusCode).json({ error: error.publicMessage });
  }
  // La configuracion del MFA depende de una variable de entorno del servidor.
  if (error.code === 'TOTP_KEY_MISSING' || error.code === 'TOTP_KEY_INVALID') {
    return response.status(500).json({ error: 'MFA is not configured on the server' });
  }
  return next(error);
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
  // El registro ejecuta un bcrypt cost 12 por intento y responde 409 si el email
  // ya existe: sin limite seria a la vez un oraculo de enumeracion y un vector
  // de agotamiento de CPU para el servidor.
  const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many registration attempts. Try again later.' },
  });
  // El verificador de codigos es la puerta mas sensible: limite corto y generoso
  // solo en ventana, para que un atacante no pruebe codigos indefinidamente.
  const mfaVerifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many verification attempts. Try again later.' },
  });
  const mfaSetupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many MFA configuration attempts. Try again later.' },
  });
  const mfaDisableLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many MFA disable attempts. Try again later.' },
  });

  // Valida, rehashea y persiste solo el material derivado que prepara el cliente.
  // POST /register: almacena el Auth Hash rehasheado y los blobs cifrados del cliente.
  router.post('/register', registerLimiter, async (request, response, next) => {
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
  // POST /login: verifica el Auth Hash y, sin MFA, devuelve la vault key envuelta junto con la sesion.
  router.post('/login', loginLimiter, async (request, response, next) => {
    const payload = parsePayload(loginSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid login payload' });
    }

    const email = payload.email;
    try {
      const result = await dbPool.query(
        `SELECT id, auth_hash_hashed, wrapped_vault_key, wrap_iv, session_version, mfa_enabled
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

      // Con MFA activo NO se entrega la vault key ni se firma la sesion: solo
      // un reto efimero que da derecho a POST /mfa/verify tras validar el codigo.
      if (user.mfa_enabled) {
        const mfaToken = jwt.sign(
          { sub: String(user.id), sv: user.session_version, purpose: 'mfa' },
          getJwtSecret(),
          { algorithm: 'HS256', expiresIn: '5m' },
        );
        response.cookie(MFA_COOKIE_NAME, mfaToken, getMfaCookieOptions());
        return response.json({ mfaRequired: true });
      }

      signSessionCookie(response, user);
      return response.json({ wrappedVaultKey: user.wrapped_vault_key, wrapIv: user.wrap_iv });
    } catch (error) {
      return next(error);
    }
  });

  // ── MFA basado en TOTP ─────────────────────────────────────────────────────
  // GET /mfa/status: indica si la cuenta tiene el segundo factor activo.
  router.get('/mfa/status', requireAuth({ dbPool }), async (request, response, next) => {
    try {
      const result = await dbPool.query('SELECT mfa_enabled FROM users WHERE id = $1', [request.user.id]);
      const user = result.rows[0];
      if (!user) return response.status(401).json({ error: 'Authentication required' });
      return response.json({ enabled: Boolean(user.mfa_enabled) });
    } catch (error) {
      return next(error);
    }
  });

  // POST /mfa/setup: genera y guarda (cifrado) un secreto pendiente de confirmar.
  // El secreto se devuelve en claro una unica vez por el canal autenticado para
  // que el cliente muestre el QR; a partir de ahi solo vive cifrado en la BD.
  router.post('/mfa/setup', mfaSetupLimiter, requireAuth({ dbPool }), async (request, response, next) => {
    try {
      const result = await dbPool.query(
        'SELECT id, email, mfa_enabled FROM users WHERE id = $1',
        [request.user.id],
      );
      const user = result.rows[0];
      if (!user) return response.status(401).json({ error: 'Authentication required' });
      if (user.mfa_enabled) return response.status(409).json({ error: 'MFA is already enabled' });

      const secret = generateTotpSecret();
      await dbPool.query(
        `UPDATE users SET mfa_secret = $1, mfa_last_counter = 0, mfa_setup_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [encryptSecret(secret), request.user.id],
      );
      return response.json({ secret, otpauthUri: buildOtpauthUri(secret, user.email) });
    } catch (error) {
      return respondMfaError(error, response, next);
    }
  });

  // POST /mfa/enable: confirma el secreto pendiente con un codigo valido, emite
  // los backup codes (unico momento en que se ven) y revoca las demas sesiones
  // incrementando session_version; la cookie actual se re-firma con el nuevo sv.
  router.post('/mfa/enable', mfaSetupLimiter, requireAuth({ dbPool }), async (request, response, next) => {
    const payload = parsePayload(mfaCodeSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid MFA payload' });
    }

    try {
      const outcome = await withTransaction(dbPool, async (client) => {
        const result = await client.query(
          'SELECT id, email, mfa_secret, mfa_enabled FROM users WHERE id = $1 FOR UPDATE',
          [request.user.id],
        );
        const user = result.rows[0];
        if (!user || !user.mfa_secret || user.mfa_enabled) {
          const error = new Error('MFA setup is not pending');
          error.statusCode = 409;
          error.publicMessage = 'MFA setup is not pending';
          throw error;
        }

        // El codigo de confirmacion NO consume el contador anti-replay: solo se
        // registran los codigos usados al iniciar sesion. Asi, el usuario puede
        // salir y volver a entrar de inmediato con el mismo codigo que acaba de
        // ver al activar, sin abrir una ventana de reutilizacion relevante
        // (entrar exige tambien la contrasena maestra).
        const confirmed = verifyTotpCode(decryptSecret(user.mfa_secret), payload.code) !== null;
        if (!confirmed) {
          const error = new Error('Invalid verification code');
          error.statusCode = 401;
          error.publicMessage = 'Invalid verification code';
          throw error;
        }

        // Los codigos de respaldo se generan aqui; bcrypt cost 12, sin texto plano en BD.
        const backupCodes = generateBackupCodes();
        await client.query('DELETE FROM mfa_backup_codes WHERE user_id = $1', [request.user.id]);
        for (const backupCode of backupCodes) {
          await client.query(
            'INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)',
            [request.user.id, await hashBackupCode(backupCode)],
          );
        }

        await client.query(
          `UPDATE users SET mfa_enabled = TRUE, mfa_setup_at = NULL,
             session_version = session_version + 1
           WHERE id = $1`,
          [request.user.id],
        );
        const versionResult = await client.query(
          'SELECT session_version FROM users WHERE id = $1',
          [request.user.id],
        );
        return { sessionVersion: versionResult.rows[0].session_version, backupCodes };
      });

      signSessionCookie(response, { id: request.user.id, session_version: outcome.sessionVersion });
      return response.json({ backupCodes: outcome.backupCodes });
    } catch (error) {
      return respondMfaError(error, response, next);
    }
  });

  // POST /mfa/verify: segundo paso del login. Acepta un codigo TOTP sin
  // reutilizar (anti-replay) o un backup code de un solo uso, y solo entonces
  // entrega la vault key y firma la sesion definitiva.
  router.post('/mfa/verify', mfaVerifyLimiter, requireMfaPending({ dbPool }), async (request, response, next) => {
    const payload = parsePayload(mfaCodeSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid MFA payload' });
    }

    try {
      const code = payload.code;
      let matchedCounter = null;
      let usedBackupCode = false;

      if (/^\d{6}$/.test(code)) {
        matchedCounter = verifyTotpCode(decryptSecret(request.user.mfaSecret), code);
        if (matchedCounter === null) {
          return response.status(401).json({ error: 'Invalid verification code' });
        }
      } else {
        const pendingCodes = await dbPool.query(
          'SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL',
          [request.user.id],
        );
        const matchedRow = await findMatchingBackupCode(code, pendingCodes.rows);
        if (!matchedRow) {
          return response.status(401).json({ error: 'Invalid verification code' });
        }
        // Reclamo atomico del codigo de respaldo: la condicion used_at IS NULL
        // garantiza que, ante dos peticiones concurrentes con el mismo codigo,
        // solo una lo marque como usado; la otra recibe rowCount 0 y se rechaza.
        const claimedCode = await dbPool.query(
          'UPDATE mfa_backup_codes SET used_at = CURRENT_TIMESTAMP WHERE id = $1 AND used_at IS NULL',
          [matchedRow.id],
        );
        if (claimedCode.rowCount === 0) {
          return response.status(401).json({ error: 'Invalid verification code' });
        }
        usedBackupCode = true;
      }

      if (usedBackupCode) {
        // El uso de un backup code resetea el contador para que los codigos
        // TOTP futuros no queden bloqueados por pasos antiguos ya consumidos.
        await dbPool.query('UPDATE users SET mfa_last_counter = 0 WHERE id = $1', [request.user.id]);
      } else {
        // Reclamo atomico del time-step: es el propio anti-replay, no un mero
        // almacenamiento. AND mfa_last_counter < $1 hace que el UPDATE solo
        // tenga exito si nadie consumio ese paso; ante peticiones concurrentes
        // con el mismo codigo, PostgreSQL serializa por bloqueo de fila, una
        // obtiene rowCount 1 y la otra rowCount 0 -> 401.
        const claimedStep = await dbPool.query(
          'UPDATE users SET mfa_last_counter = $1 WHERE id = $2 AND mfa_last_counter < $1',
          [matchedCounter, request.user.id],
        );
        if (claimedStep.rowCount === 0) {
          return response.status(401).json({ error: 'Invalid verification code' });
        }
      }

      const userResult = await dbPool.query(
        'SELECT id, session_version, wrapped_vault_key, wrap_iv FROM users WHERE id = $1',
        [request.user.id],
      );
      const user = userResult.rows[0];
      if (!user) return response.status(401).json({ error: 'MFA verification required' });

      response.clearCookie(MFA_COOKIE_NAME, getMfaCookieOptions());
      signSessionCookie(response, user);
      return response.json({
        wrappedVaultKey: user.wrapped_vault_key,
        wrapIv: user.wrap_iv,
        ...(usedBackupCode ? { usedBackupCode: true } : {}),
      });
    } catch (error) {
      return respondMfaError(error, response, next);
    }
  });

  // POST /mfa/disable: exige posesion del segundo factor (codigo o backup code)
  // para desactivarlo; un ladron de cookie de sesion no podria apagar el MFA.
  router.post('/mfa/disable', mfaDisableLimiter, requireAuth({ dbPool }), async (request, response, next) => {
    const payload = parsePayload(mfaCodeSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid MFA payload' });
    }

    try {
      const sessionVersion = await withTransaction(dbPool, async (client) => {
        const result = await client.query(
          'SELECT id, mfa_secret, mfa_enabled FROM users WHERE id = $1 FOR UPDATE',
          [request.user.id],
        );
        const user = result.rows[0];
        if (!user || !user.mfa_enabled || !user.mfa_secret) {
          const error = new Error('MFA is not enabled');
          error.statusCode = 409;
          error.publicMessage = 'MFA is not enabled';
          throw error;
        }

        let authorized = false;
        if (/^\d{6}$/.test(payload.code)) {
          authorized = verifyTotpCode(decryptSecret(user.mfa_secret), payload.code) !== null;
        } else {
          const codeRows = await client.query(
            'SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL',
            [request.user.id],
          );
          authorized = (await findMatchingBackupCode(payload.code, codeRows.rows)) !== null;
        }
        if (!authorized) {
          const error = new Error('Invalid verification code');
          error.statusCode = 401;
          error.publicMessage = 'Invalid verification code';
          throw error;
        }

        await client.query('DELETE FROM mfa_backup_codes WHERE user_id = $1', [request.user.id]);
        await client.query(
          `UPDATE users SET mfa_secret = NULL, mfa_enabled = FALSE, mfa_last_counter = 0,
             mfa_setup_at = NULL, session_version = session_version + 1
           WHERE id = $1`,
          [request.user.id],
        );
        const versionResult = await client.query(
          'SELECT session_version FROM users WHERE id = $1',
          [request.user.id],
        );
        return versionResult.rows[0].session_version;
      });

      signSessionCookie(response, { id: request.user.id, session_version: sessionVersion });
      return response.sendStatus(204);
    } catch (error) {
      return respondMfaError(error, response, next);
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

  const deleteAccountLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many account deletion attempts. Try again later.' },
  });

  // DELETE /account: elimina la cuenta y todos sus vault_items en una transaccion.
  router.delete('/account', deleteAccountLimiter, requireAuth({ dbPool }), async (request, response, next) => {
    const payload = parsePayload(deleteAccountSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid delete account payload' });
    }

    try {
      await withTransaction(dbPool, async (client) => {
        const result = await client.query(
          'SELECT auth_hash_hashed FROM users WHERE id = $1 FOR UPDATE',
          [request.user.id],
        );
        const user = result.rows[0];
        const valid = user && await bcrypt.compare(payload.authHash, user.auth_hash_hashed);
        if (!valid) {
          const error = new Error('Invalid credentials');
          error.statusCode = 401;
          throw error;
        }

        await client.query('DELETE FROM vault_items WHERE user_id = $1', [request.user.id]);
        await client.query('DELETE FROM mfa_backup_codes WHERE user_id = $1', [request.user.id]);
        await client.query('DELETE FROM users WHERE id = $1', [request.user.id]);
      });

      response.clearCookie(JWT_COOKIE_NAME, getSessionCookieOptions());
      return response.sendStatus(204);
    } catch (error) {
      if (error.statusCode === 401) return response.status(401).json({ error: 'Invalid credentials' });
      return next(error);
    }
  });

  // Evita exponer detalles de base de datos o criptografia en respuestas de error.
  router.use((error, _request, response, _next) => {
    response.status(500).json({ error: 'Internal server error' });
  });

  return router;
}

module.exports = { createAuthRouter };