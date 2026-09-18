const test = require('node:test');
const assert = require('node:assert/strict');

process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.JWT_SECRET = 'test-secret-with-at-least-32-characters';
process.env.COOKIE_SECURE = 'true';

const request = require('supertest');
const bcrypt = require('bcryptjs');
const { createApp } = require('../src/app');

/** Crea un almacenamiento en memoria con la misma interfaz minima que pg.Pool. */
function makePool() {
  const users = new Map();
  return {
    users,
    async query(sql, params) {
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
        });
        return { rowCount: 1, rows: [] };
      }

      if (sql.includes('kdf_salt')) {
        const user = users.get(params[0]);
        return { rows: user ? [user] : [] };
      }

      if (sql.includes('auth_hash_hashed')) {
        const user = users.get(params[0]);
        return { rows: user ? [user] : [] };
      }

      throw new Error(`Unexpected query: ${sql}`);
    },
  };
}

/** Genera el payload criptografico que el cliente enviaria despues de derivar sus claves. */
function validRegistration(email = 'alice@example.com') {
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