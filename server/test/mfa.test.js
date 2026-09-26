const test = require('node:test');
const assert = require('node:assert/strict');

process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.JWT_SECRET = 'test-secret-with-at-least-32-characters';
process.env.COOKIE_SECURE = 'true';
process.env.TOTP_ENC_KEY = require('node:crypto').randomBytes(32).toString('base64');

// Contrato HTTP del MFA: login en dos pasos, enable/disable y anti-replay.
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Secret, TOTP } = require('otpauth');
const { createApp } = require('../src/app');
const { encryptSecret, generateTotpSecret } = require('../src/totp-secret');

const AUTH_HASH = Buffer.alloc(32, 2).toString('base64');
// Se hashea una sola vez para no pagar coste 12 en cada test.
const AUTH_HASH_HASHED = bcrypt.hashSync(AUTH_HASH, 12);
const WRAPPED_VAULT_KEY = Buffer.alloc(48, 3).toString('base64');
const WRAP_IV = Buffer.alloc(12, 4).toString('base64');

/** Almacenamiento en memoria con la interfaz minima de pg.Pool para las rutas MFA. */
function makePool() {
  const users = new Map();
  const backupCodes = [];
  let nextBackupId = 1;

  const findById = (id) => [...users.values()].find((candidate) => String(candidate.id) === String(id));

  return {
    users,
    backupCodes,
    async query(sql, params) {
      const q = sql.trim();
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(q)) return { rows: [] };

      if (q.includes('FROM users WHERE email')) {
        const user = [...users.values()].find((candidate) => candidate.email === params[0]);
        return { rows: user ? [{ ...user }] : [] };
      }
      if (q.includes('FROM users WHERE id')) {
        const user = findById(params[0]);
        return { rows: user ? [{ ...user }] : [] };
      }

      if (q.startsWith('SELECT') && q.includes('mfa_backup_codes')) {
        const rows = backupCodes
          .filter((code) => String(code.user_id) === String(params[0]))
          .filter((code) => q.includes('used_at IS NULL') ? code.used_at === null : true)
          .map((code) => ({ ...code }));
        return { rows };
      }
      if (q.startsWith('INSERT INTO mfa_backup_codes')) {
        backupCodes.push({ id: nextBackupId++, user_id: params[0], code_hash: params[1], used_at: null });
        return { rows: [], rowCount: 1 };
      }
      if (q.startsWith('UPDATE mfa_backup_codes')) {
        const code = backupCodes.find((candidate) => String(candidate.id) === String(params[0]));
        // Replica la condicion AND used_at IS NULL del reclamo atomico.
        if (code && q.includes('used_at IS NULL') && code.used_at !== null) {
          return { rows: [], rowCount: 0 };
        }
        if (code) code.used_at = '2026-01-01 00:00:00';
        return { rows: [], rowCount: code ? 1 : 0 };
      }
      if (q.startsWith('DELETE FROM mfa_backup_codes')) {
        for (let index = backupCodes.length - 1; index >= 0; index -= 1) {
          if (String(backupCodes[index].user_id) === String(params[0])) backupCodes.splice(index, 1);
        }
        return { rows: [], rowCount: 0 };
      }

      if (q.startsWith('UPDATE users')) {
        // El orden de estas ramas replica el orden de las clausulas SET de cada ruta.
        if (q.includes('mfa_setup_at = CURRENT_TIMESTAMP')) {
          const user = findById(params[1]);
          user.mfa_secret = params[0];
          user.mfa_last_counter = 0;
          user.mfa_setup_at = '2026-01-01 00:00:00';
          return { rows: [], rowCount: 1 };
        }
        if (q.includes('mfa_enabled = TRUE')) {
          const user = findById(params[0]);
          user.mfa_enabled = true;
          user.mfa_setup_at = null;
          user.session_version += 1;
          return { rows: [], rowCount: 1 };
        }
        if (q.includes('mfa_enabled = FALSE')) {
          const user = findById(params[0]);
          user.mfa_secret = null;
          user.mfa_enabled = false;
          user.mfa_last_counter = 0;
          user.mfa_setup_at = null;
          user.session_version += 1;
          return { rows: [], rowCount: 1 };
        }
        if (q.includes('SET mfa_last_counter = 0 WHERE id')) {
          const user = findById(params[0]);
          user.mfa_last_counter = 0;
          return { rows: [], rowCount: 1 };
        }
        if (q.includes('SET mfa_last_counter = $1')) {
          const user = findById(params[1]);
          // Replica el reclamo atomico: AND mfa_last_counter < $1.
          if (user.mfa_last_counter >= params[0]) {
            return { rows: [], rowCount: 0 };
          }
          user.mfa_last_counter = params[0];
          return { rows: [], rowCount: 1 };
        }
        throw new Error(`Unexpected user update: ${sql}`);
      }

      throw new Error(`Unexpected query: ${sql}`);
    },
    async connect() {
      return { query: this.query.bind(this), release() {} };
    },
  };
}

/** Cuenta de prueba con el Auth Hash conocido; el MFA arranca desactivado por defecto. */
function seedUser(pool, email, { mfaEnabled = false, mfaSecret = null } = {}) {
  const user = {
    id: pool.users.size + 1,
    email,
    kdf_salt: Buffer.alloc(16, 1).toString('base64'),
    kdf_iterations: 600000,
    auth_hash_hashed: AUTH_HASH_HASHED,
    wrapped_vault_key: WRAPPED_VAULT_KEY,
    wrap_iv: WRAP_IV,
    session_version: 0,
    mfa_secret: mfaSecret,
    mfa_enabled: mfaEnabled,
    mfa_last_counter: 0,
    mfa_setup_at: null,
  };
  pool.users.set(email, user);
  return user;
}

/** Cookie de sesion valida para un usuario del mock (mismo contrato que requireAuth). */
function sessionCookie(userId, sessionVersion = 0) {
  const token = jwt.sign({ sub: String(userId), sv: sessionVersion }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '8h',
  });
  return `session=${token}`;
}

/** Extrae una cookie concreta de la lista Set-Cookie de una respuesta. */
function pickCookie(setCookieHeaders, name) {
  const header = (setCookieHeaders || []).find((entry) => entry.startsWith(`${name}=`));
  return header ? header.split(';')[0] : null;
}

/** Genera un codigo TOTP valido para un secreto en un instante dado. */
function currentTotpCode(secret, timestamp = Date.now()) {
  const totp = new TOTP({ secret: Secret.fromBase32(secret), algorithm: 'SHA1', digits: 6, period: 30 });
  return totp.generate({ timestamp });
}

/** Codigo que nunca puede casar con el verdadero (complemento a 9 de cada digito). */
function wrongTotpCode(secret, timestamp = Date.now()) {
  const valid = currentTotpCode(secret, timestamp);
  return valid.split('').map((digit) => String((9 - Number(digit)) % 10)).join('');
}

// Sin MFA el contrato antiguo se conserva exactamente: vault key en el primer paso.
test('login without MFA keeps the original single-step contract', async () => {
  const pool = makePool();
  seedUser(pool, 'plain@example.com');
  const app = createApp({ dbPool: pool });

  const response = await request(app).post('/api/auth/login').send({ email: 'plain@example.com', authHash: AUTH_HASH });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { wrappedVaultKey: WRAPPED_VAULT_KEY, wrapIv: WRAP_IV });
  assert.ok(pickCookie(response.headers['set-cookie'], 'session'));
  assert.equal(pickCookie(response.headers['set-cookie'], 'mfa'), null);
});

// Con MFA activo la respuesta solo puede contener el reto: jamas la vault key.
test('login with MFA returns only an ephemeral challenge without the vault key', async () => {
  const pool = makePool();
  seedUser(pool, 'mfa@example.com', { mfaEnabled: true, mfaSecret: encryptSecret(generateTotpSecret()) });
  const app = createApp({ dbPool: pool });

  const response = await request(app).post('/api/auth/login').send({ email: 'mfa@example.com', authHash: AUTH_HASH });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { mfaRequired: true });
  assert.equal(response.body.wrappedVaultKey, undefined);
  assert.equal(response.body.wrapIv, undefined);

  const mfaCookie = pickCookie(response.headers['set-cookie'], 'mfa');
  assert.ok(mfaCookie, 'debe emitirse la cookie intermedia mfa');
  assert.match(response.headers['set-cookie'].join(' '), /HttpOnly/);
  assert.match(response.headers['set-cookie'].join(' '), /SameSite=Strict/);
  assert.match(response.headers['set-cookie'].join(' '), /Max-Age=300/);

  // El reto lleva el proposito 'mfa' para no confundirse con una sesion real.
  const claims = jwt.decode(mfaCookie.slice('mfa='.length));
  assert.equal(claims.purpose, 'mfa');
});

// Flujo completo del segundo paso: codigo valido entra, el mismo codigo no se reutiliza.
test('verify accepts a valid TOTP code once and rejects its replay', async () => {
  const pool = makePool();
  const secret = generateTotpSecret();
  seedUser(pool, 'verify@example.com', { mfaEnabled: true, mfaSecret: encryptSecret(secret) });
  const app = createApp({ dbPool: pool });

  const login = await request(app).post('/api/auth/login').send({ email: 'verify@example.com', authHash: AUTH_HASH });
  const challenge = pickCookie(login.headers['set-cookie'], 'mfa');

  const badPayload = await request(app).post('/api/auth/mfa/verify').set('Cookie', [challenge]).send({ code: '12' });
  assert.equal(badPayload.status, 400);

  const verified = await request(app)
    .post('/api/auth/mfa/verify')
    .set('Cookie', [challenge])
    .send({ code: currentTotpCode(secret) });
  assert.equal(verified.status, 200);
  assert.deepEqual(verified.body, { wrappedVaultKey: WRAPPED_VAULT_KEY, wrapIv: WRAP_IV });
  const setCookies = verified.headers['set-cookie'];
  assert.ok(pickCookie(setCookies, 'session'), 'debe firmarse la sesion definitiva');
  assert.ok(setCookies.some((entry) => entry.startsWith('mfa=;')), 'el reto debe quedar invalidado');

  // Replay: se pide un reto nuevo y se reintenta el mismo codigo ya consumido.
  const secondLogin = await request(app).post('/api/auth/login').send({ email: 'verify@example.com', authHash: AUTH_HASH });
  const secondChallenge = pickCookie(secondLogin.headers['set-cookie'], 'mfa');
  const replay = await request(app)
    .post('/api/auth/mfa/verify')
    .set('Cookie', [secondChallenge])
    .send({ code: currentTotpCode(secret) });
  assert.equal(replay.status, 401);
  assert.deepEqual(replay.body, { error: 'Invalid verification code' });
});

// El sexto intento de codigo invalido queda bloqueado por el rate limit.
test('blocks the sixth failed MFA verification attempt', async () => {
  const pool = makePool();
  const secret = generateTotpSecret();
  seedUser(pool, 'brute@example.com', { mfaEnabled: true, mfaSecret: encryptSecret(secret) });
  const app = createApp({ dbPool: pool });

  const login = await request(app).post('/api/auth/login').send({ email: 'brute@example.com', authHash: AUTH_HASH });
  const challenge = pickCookie(login.headers['set-cookie'], 'mfa');
  const wrongCode = wrongTotpCode(secret);

  const responses = [];
  for (let attempt = 0; attempt < 6; attempt += 1) {
    responses.push(await request(app).post('/api/auth/mfa/verify').set('Cookie', [challenge]).send({ code: wrongCode }));
  }

  assert.deepEqual(responses.slice(0, 5).map((response) => response.status), [401, 401, 401, 401, 401]);
  assert.equal(responses[5].status, 429);
});

// Ciclo de vida completo: setup -> enable (con backup codes) -> status -> disable.
test('runs the full MFA lifecycle from setup to disable', async () => {
  const pool = makePool();
  seedUser(pool, 'life@example.com');
  const app = createApp({ dbPool: pool });
  const cookie = sessionCookie(1);

  const statusBefore = await request(app).get('/api/auth/mfa/status').set('Cookie', [cookie]);
  assert.deepEqual(statusBefore.body, { enabled: false });

  const setup = await request(app).post('/api/auth/mfa/setup').set('Cookie', [cookie]);
  assert.equal(setup.status, 200);
  assert.match(setup.body.secret, /^[A-Z2-7]{32}$/);
  assert.ok(setup.body.otpauthUri.startsWith('otpauth://totp/Arca:'));
  assert.ok(setup.body.otpauthUri.includes(`secret=${setup.body.secret}`));
  // El secreto queda cifrado en la base de datos, jamas en claro.
  assert.notEqual(pool.users.get('life@example.com').mfa_secret, setup.body.secret);
  assert.match(pool.users.get('life@example.com').mfa_secret, /^[A-Za-z0-9+/]+:[A-Za-z0-9+/]+$/);
  // Setup deja marcado el alta pendiente en mfa_setup_at.
  assert.ok(pool.users.get('life@example.com').mfa_setup_at);

  const statusPending = await request(app).get('/api/auth/mfa/status').set('Cookie', [cookie]);
  assert.deepEqual(statusPending.body, { enabled: false });

  const enabled = await request(app)
    .post('/api/auth/mfa/enable')
    .set('Cookie', [cookie])
    .send({ code: currentTotpCode(setup.body.secret) });
  assert.equal(enabled.status, 200);
  assert.equal(enabled.body.backupCodes.length, 10);
  for (const backupCode of enabled.body.backupCodes) {
    assert.match(backupCode, /^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
  }
  // Enable incrementa session_version: las cookies anteriores mueren y la actual se re-firma.
  const reissued = pickCookie(enabled.headers['set-cookie'], 'session');
  assert.equal(jwt.decode(reissued.slice('session='.length)).sv, 1);
  assert.equal(pool.users.get('life@example.com').mfa_enabled, true);
  // Enable confirma el alta y limpia la marca de pendiente.
  assert.equal(pool.users.get('life@example.com').mfa_setup_at, null);

  const statusAfter = await request(app).get('/api/auth/mfa/status').set('Cookie', [reissued]);
  assert.deepEqual(statusAfter.body, { enabled: true });

  const setupAgain = await request(app).post('/api/auth/mfa/setup').set('Cookie', [reissued]);
  assert.equal(setupAgain.status, 409);

  const disabled = await request(app)
    .post('/api/auth/mfa/disable')
    .set('Cookie', [reissued])
    .send({ code: currentTotpCode(setup.body.secret) });
  assert.equal(disabled.status, 204);
  const user = pool.users.get('life@example.com');
  assert.equal(user.mfa_enabled, false);
  assert.equal(user.mfa_secret, null);
  assert.equal(user.mfa_last_counter, 0);
  assert.equal(user.session_version, 2);

  const loginAfter = await request(app).post('/api/auth/login').send({ email: 'life@example.com', authHash: AUTH_HASH });
  assert.equal(loginAfter.status, 200);
  assert.deepEqual(loginAfter.body, { wrappedVaultKey: WRAPPED_VAULT_KEY, wrapIv: WRAP_IV });
});

// Un backup code permite entrar una sola vez y luego queda agotado.
test('accepts a backup code once at login and rejects its reuse', async () => {
  const pool = makePool();
  seedUser(pool, 'backup@example.com');
  const app = createApp({ dbPool: pool });
  const cookie = sessionCookie(1);

  const setup = await request(app).post('/api/auth/mfa/setup').set('Cookie', [cookie]);
  const enabled = await request(app)
    .post('/api/auth/mfa/enable')
    .set('Cookie', [cookie])
    .send({ code: currentTotpCode(setup.body.secret) });
  const backupCode = enabled.body.backupCodes[0];

  const login = await request(app).post('/api/auth/login').send({ email: 'backup@example.com', authHash: AUTH_HASH });
  const challenge = pickCookie(login.headers['set-cookie'], 'mfa');
  const verified = await request(app).post('/api/auth/mfa/verify').set('Cookie', [challenge]).send({ code: backupCode });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.usedBackupCode, true);
  assert.equal(verified.body.wrappedVaultKey, WRAPPED_VAULT_KEY);
  assert.equal(pool.backupCodes.filter((code) => code.used_at !== null).length, 1);

  const secondLogin = await request(app).post('/api/auth/login').send({ email: 'backup@example.com', authHash: AUTH_HASH });
  const secondChallenge = pickCookie(secondLogin.headers['set-cookie'], 'mfa');
  const reuse = await request(app)
    .post('/api/auth/mfa/verify')
    .set('Cookie', [secondChallenge])
    .send({ code: backupCode });
  assert.equal(reuse.status, 401);
});

// Desactivar exige posesion del segundo factor y revoca la cookie anterior.
test('disable requires a valid second factor and revokes older sessions', async () => {
  const pool = makePool();
  const secret = generateTotpSecret();
  seedUser(pool, 'guard@example.com', { mfaEnabled: true, mfaSecret: encryptSecret(secret) });
  const app = createApp({ dbPool: pool });
  const oldCookie = sessionCookie(1, 0);

  const wrong = await request(app)
    .post('/api/auth/mfa/disable')
    .set('Cookie', [oldCookie])
    .send({ code: wrongTotpCode(secret) });
  assert.equal(wrong.status, 401);

  const withoutSession = await request(app).post('/api/auth/mfa/disable').send({ code: currentTotpCode(secret) });
  assert.equal(withoutSession.status, 401);

  const disabled = await request(app)
    .post('/api/auth/mfa/disable')
    .set('Cookie', [oldCookie])
    .send({ code: currentTotpCode(secret) });
  assert.equal(disabled.status, 204);

  const freshCookie = pickCookie(disabled.headers['set-cookie'], 'session');
  assert.equal(jwt.decode(freshCookie.slice('session='.length)).sv, 1);
  // La cookie anterior (sv 0) queda invalidada por el incremento de session_version.
  const revoked = await request(app).get('/api/auth/mfa/status').set('Cookie', [oldCookie]);
  assert.equal(revoked.status, 401);

  const notEnabled = await request(app)
    .post('/api/auth/mfa/disable')
    .set('Cookie', [freshCookie])
    .send({ code: currentTotpCode(secret) });
  assert.equal(notEnabled.status, 409);
});

// Ninguna ruta MFA funciona sin la cookie correspondiente.
test('rejects MFA requests without the required cookies', async () => {
  const pool = makePool();
  seedUser(pool, 'anon@example.com', { mfaEnabled: true, mfaSecret: encryptSecret(generateTotpSecret()) });
  const app = createApp({ dbPool: pool });

  assert.equal((await request(app).get('/api/auth/mfa/status')).status, 401);
  assert.equal((await request(app).post('/api/auth/mfa/setup')).status, 401);
  assert.equal((await request(app).post('/api/auth/mfa/enable').send({ code: '123456' })).status, 401);
  assert.equal((await request(app).post('/api/auth/mfa/disable').send({ code: '123456' })).status, 401);

  // Una sesion normal no sirve como reto intermedio: el proposito del JWT difiere.
  const sessionAsChallenge = sessionCookie(1);
  assert.equal(
    (await request(app).post('/api/auth/mfa/verify').set('Cookie', [sessionAsChallenge]).send({ code: '123456' })).status,
    401,
  );
  assert.equal((await request(app).post('/api/auth/mfa/verify').send({ code: '123456' })).status, 401);
});

// Sin la clave de entorno el servidor no puede guardar secretos y lo dice claro.
test('reports a clear error when TOTP_ENC_KEY is missing', async () => {
  const pool = makePool();
  seedUser(pool, 'nokey@example.com');
  const app = createApp({ dbPool: pool });
  const cookie = sessionCookie(1);
  const originalKey = process.env.TOTP_ENC_KEY;
  delete process.env.TOTP_ENC_KEY;

  try {
    const response = await request(app).post('/api/auth/mfa/setup').set('Cookie', [cookie]);
    assert.equal(response.status, 500);
    assert.deepEqual(response.body, { error: 'MFA is not configured on the server' });
  } finally {
    process.env.TOTP_ENC_KEY = originalKey;
  }
});
