const test = require('node:test');
const assert = require('node:assert/strict');

process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.JWT_SECRET = 'test-secret-with-at-least-32-characters';
process.env.COOKIE_SECURE = 'true';

// Dependencias HTTP y de hashing usadas para probar el contrato sin una base real.
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createApp } = require('../src/app');

/** Crea un almacenamiento en memoria con la misma interfaz minima que pg.Pool. */
function makePool() {
  // Simula las consultas que usan las rutas de autenticacion y conserva sus resultados.
  const users = new Map();
  return {
    users,
    async query(sql, params) {
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
      if (sql.startsWith('SELECT session_version FROM users')) {
        const user = [...users.values()].find((candidate) => String(candidate.id) === params[0]);
        return { rows: user ? [user] : [] };
      }
      if (sql.startsWith('INSERT INTO users')) {
        const [email, kdfSalt, kdfIterations, authHashHashed, wrappedVaultKey, wrapIv] = params;
        if (users.has(email)) {
          const error = new Error('duplicate');
          error.code = '23505';
          throw error;
        }
        users.set(email, {
          id: users.size + 1,
          email,
          kdf_salt: kdfSalt,
          kdf_iterations: kdfIterations,
          auth_hash_hashed: authHashHashed,
          wrapped_vault_key: wrappedVaultKey,
          wrap_iv: wrapIv,
          session_version: 0,
        });
        return { rowCount: 1, rows: [] };
      }

      if (sql.trim().startsWith('UPDATE users')) {
        const user = [...users.values()].find((candidate) => String(candidate.id) === params[5]);
        if (!user) return { rowCount: 0 };
        user.kdf_salt = params[0];
        user.kdf_iterations = params[1];
        user.auth_hash_hashed = params[2];
        user.wrapped_vault_key = params[3];
        user.wrap_iv = params[4];
        user.session_version += 1;
        return { rowCount: 1 };
      }

      if (sql.includes('kdf_salt')) {
        const user = users.get(params[0]);
        return { rows: user ? [user] : [] };
      }

      if (sql.includes('auth_hash_hashed')) {
        const user = sql.includes('FOR UPDATE')
          ? [...users.values()].find((candidate) => String(candidate.id) === params[0])
          : users.get(params[0]);
        return { rows: user ? [user] : [] };
      }

      throw new Error(`Unexpected query: ${sql}`);
    },
    async connect() {
      return {
        query: this.query.bind(this),
        release() {},
      };
    },
  };
}

/** Genera el payload criptografico que el cliente enviaria despues de derivar sus claves. */
function validRegistration(email = 'alice@example.com') {
  // Representa el payload ya derivado que enviaria el navegador.
  return {
    email,
    kdfSalt: Buffer.alloc(16, 1).toString('base64'),
    kdfIterations: 600000,
    authHash: Buffer.alloc(32, 2).toString('base64'),
    wrappedVaultKey: Buffer.alloc(48, 3).toString('base64'),
    wrapIv: Buffer.alloc(12, 4).toString('base64'),
  };
}

// Verifica el flujo feliz y que la respuesta no expone el Auth Hash ni la Vault Key en claro.
test('registers, returns the stored salt, and logs in with a secure httpOnly cookie', async () => {
  const pool = makePool();
  const app = createApp({ dbPool: pool });
  const registration = validRegistration();

  const registerResponse = await request(app).post('/api/auth/register').send(registration);
  assert.equal(registerResponse.status, 201);
  assert.notEqual(pool.users.get(registration.email).auth_hash_hashed, registration.authHash);

  const saltResponse = await request(app).get('/api/auth/salt').query({ email: registration.email });
  assert.equal(saltResponse.status, 200);
  assert.equal(saltResponse.body.kdfSalt, registration.kdfSalt);
  assert.equal(saltResponse.body.kdfIterations, registration.kdfIterations);

  const loginResponse = await request(app).post('/api/auth/login').send(registration);
  assert.equal(loginResponse.status, 200);
  assert.deepEqual(loginResponse.body, {
    wrappedVaultKey: registration.wrappedVaultKey,
    wrapIv: registration.wrapIv,
  });
  assert.match(loginResponse.headers['set-cookie'][0], /HttpOnly/);
  assert.match(loginResponse.headers['set-cookie'][0], /Secure/);
  assert.match(loginResponse.headers['set-cookie'][0], /SameSite=Strict/);
});

test('changes the derived password material and invalidates the previous session', async () => {
  const pool = makePool();
  const app = createApp({ dbPool: pool });
  const registration = validRegistration('rotate@example.com');
  await request(app).post('/api/auth/register').send(registration);
  const loginResponse = await request(app).post('/api/auth/login').send(registration);
  const oldCookie = `session=${jwt.sign({ sub: '1', sv: 0 }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '8h',
  })}`;
  const replacement = {
    currentAuthHash: registration.authHash,
    kdfSalt: Buffer.alloc(16, 8).toString('base64'),
    kdfIterations: 600000,
    authHash: Buffer.alloc(32, 7).toString('base64'),
    wrappedVaultKey: Buffer.alloc(48, 6).toString('base64'),
    wrapIv: Buffer.alloc(12, 5).toString('base64'),
  };

  const changed = await request(app)
    .post('/api/auth/change-password')
    .set({ Cookie: [oldCookie] })
    .send(replacement);
  assert.equal(changed.status, 204);
  assert.match(changed.headers['set-cookie'][0], /session=;/);

  assert.equal((await request(app).post('/api/auth/logout').set({ Cookie: [oldCookie] })).status, 401);
  const newLogin = await request(app).post('/api/auth/login').send({
    email: registration.email,
    authHash: replacement.authHash,
  });
  assert.equal(newLogin.status, 200);
});

// Verifica que la consulta de salt no permite enumerar cuentas por su respuesta.
test('returns a deterministic fake salt for an unknown email without revealing it', async () => {
  const app = createApp({ dbPool: makePool() });
  const first = await request(app).get('/api/auth/salt').query({ email: 'missing@example.com' });
  const second = await request(app).get('/api/auth/salt').query({ email: 'missing@example.com' });

  assert.equal(first.status, 200);
  assert.deepEqual(first.body, second.body);
  assert.equal(first.body.kdfSalt.length, 24);
  assert.equal(first.body.kdfIterations, 600000);
});

// Verifica que un email inexistente recibe el mismo error que una credencial incorrecta.
test('returns the same invalid-credentials response for an unknown email', async () => {
  const app = createApp({ dbPool: makePool() });
  const response = await request(app).post('/api/auth/login').send(validRegistration('missing@example.com'));

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, { error: 'Invalid credentials' });
});

// Verifica el limite requerido: cinco fallos se aceptan y el sexto queda bloqueado.
test('blocks the sixth failed login attempt', async () => {
  const pool = makePool();
  const app = createApp({ dbPool: pool });
  const registration = validRegistration('blocked@example.com');
  await request(app).post('/api/auth/register').send(registration);

  const invalidCredentials = { ...registration, authHash: Buffer.alloc(32, 9).toString('base64') };
  const responses = [];
  for (let attempt = 0; attempt < 6; attempt += 1) {
    responses.push(await request(app).post('/api/auth/login').send(invalidCredentials));
  }

  assert.deepEqual(responses.slice(0, 5).map((response) => response.status), [401, 401, 401, 401, 401]);
  assert.equal(responses[5].status, 429);
});

// Verifica que los cuerpos invalidos fallan con 400 en lugar de producir un error interno.
test('rejects malformed registration and login payloads with 400', async () => {
  const app = createApp({ dbPool: makePool() });
  const malformed = { email: 'alice@example.com', authHash: 'not-base64' };

  assert.equal((await request(app).post('/api/auth/register').send(malformed)).status, 400);
  assert.equal((await request(app).post('/api/auth/login').send(malformed)).status, 400);
});

test('rejects emails longer than the protocol limit', async () => {
  const app = createApp({ dbPool: makePool() });
  const oversized = validRegistration(`${'a'.repeat(245)}@example.com`);

  assert.equal((await request(app).post('/api/auth/register').send(oversized)).status, 400);
  assert.equal((await request(app).post('/api/auth/login').send(oversized)).status, 400);
});

test('sends a strict CSP and only allows the configured frontend origin', async () => {
  const app = createApp({ dbPool: makePool() });
  const allowed = await request(app)
    .get('/health')
    .set('Origin', 'http://localhost:5173');
  const denied = await request(app)
    .get('/health')
    .set('Origin', 'https://untrusted.example');

  assert.match(allowed.headers['content-security-policy'], /default-src 'self'/);
  assert.doesNotMatch(allowed.headers['content-security-policy'], /unsafe-inline|unsafe-eval/);
  assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:5173');
  assert.equal(allowed.headers['access-control-allow-credentials'], 'true');
  assert.notEqual(denied.headers['access-control-allow-origin'], 'https://untrusted.example');
});