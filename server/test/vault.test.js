const test = require('node:test');
const assert = require('node:assert/strict');

process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.JWT_SECRET = 'test-secret-with-at-least-32-characters';
process.env.COOKIE_SECURE = 'false';

// Estas pruebas ejercitan las rutas privadas sin tocar PostgreSQL.
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { createApp } = require('../src/app');

function makePool() {
  // Conserva blobs por usuario para poder verificar el aislamiento del CRUD.
  const items = [];
  return {
    items,
    async query(sql, params) {
      if (sql.includes('SELECT id, iv, ciphertext')) {
        return {
          rows: items.filter((item) => item.user_id === params[0]),
        };
      }

      if (sql.startsWith('INSERT INTO vault_items')) {
        const item = {
          id: items.length + 1,
          user_id: params[0],
          iv: params[1],
          ciphertext: params[2],
          created_at: '2026-09-18T00:00:00.000Z',
          updated_at: '2026-09-18T00:00:00.000Z',
        };
        items.push(item);
        return { rows: [{ id: item.id }] };
      }

      if (sql.startsWith('UPDATE vault_items')) {
        const item = items.find((candidate) => candidate.id === Number(params[2])
          && candidate.user_id === params[3]);
        if (!item) return { rowCount: 0 };
        item.iv = params[0];
        item.ciphertext = params[1];
        return { rowCount: 1 };
      }

      if (sql.startsWith('DELETE FROM vault_items')) {
        const index = items.findIndex((candidate) => candidate.id === Number(params[0])
          && candidate.user_id === params[1]);
        if (index === -1) return { rowCount: 0 };
        items.splice(index, 1);
        return { rowCount: 1 };
      }

      throw new Error(`Unexpected query: ${sql}`);
    },
  };
}

function sessionCookie(userId) {
  // Genera la misma cookie que emitiría el endpoint de login.
  const token = jwt.sign({ sub: userId }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '8h',
  });
  return `session=${token}`;
}

function validItem(fill = 1) {
  // Crea un blob con tamaños válidos, sin introducir contenido legible.
  return {
    iv: Buffer.alloc(12, fill).toString('base64'),
    ciphertext: Buffer.alloc(16, fill + 1).toString('base64'),
  };
}

test('requires authentication and isolates every vault operation by user', async () => {
  const pool = makePool();
  const app = createApp({ dbPool: pool });
  const userA = { Cookie: sessionCookie('1') };
  const userB = { Cookie: sessionCookie('2') };
  const item = validItem();

  assert.equal((await request(app).get('/api/vault')).status, 401);

  const created = await request(app).post('/api/vault').set(userA).send(item);
  assert.equal(created.status, 201);
  assert.deepEqual(created.body, { id: 1 });

  assert.deepEqual((await request(app).get('/api/vault').set(userB)).body, []);
  assert.equal((await request(app).put('/api/vault/1').set(userB).send(validItem(2))).status, 404);
  assert.equal((await request(app).delete('/api/vault/1').set(userB)).status, 404);

  const owned = await request(app).get('/api/vault').set(userA);
  assert.equal(owned.status, 200);
  assert.equal(owned.body[0].ciphertext, item.ciphertext);
  assert.equal((await request(app).put('/api/vault/1').set(userA).send(validItem(3))).status, 204);
  assert.equal((await request(app).delete('/api/vault/1').set(userA)).status, 204);
  assert.deepEqual((await request(app).get('/api/vault').set(userA)).body, []);
});

test('rejects malformed vault blobs before reaching persistence', async () => {
  const pool = makePool();
  const app = createApp({ dbPool: pool });
  const response = await request(app)
    .post('/api/vault')
    .set({ Cookie: sessionCookie('1') })
    .send({ iv: 'not-base64', ciphertext: 'not-base64' });

  assert.equal(response.status, 400);
  assert.equal(pool.items.length, 0);
});