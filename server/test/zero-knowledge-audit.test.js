const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const request = require('supertest');
const { createApp } = require('../src/app');
const { closeDatabase, pool } = require('../src/db');

const MARKER = 'CONTRASEÑA_DE_PRUEBA_XYZ';

function base64(value) {
  return Buffer.from(value).toString('base64');
}

function encrypt(key, plaintext, iv) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

test('database never contains the recognizable plaintext marker', {
  skip: !process.env.RUN_ZK_AUDIT,
}, async () => {
  const email = `zk-audit-${crypto.randomUUID()}@example.test`;
  const authHash = crypto.randomBytes(32);
  const vaultKey = crypto.randomBytes(32);
  const wrapIv = crypto.randomBytes(12);
  const wrappedVaultKey = encrypt(crypto.randomBytes(32), vaultKey, wrapIv);
  const itemIv = crypto.randomBytes(12);
  const plaintextItem = Buffer.from(JSON.stringify({
    title: 'Audit item',
    username: 'audit-user',
    password: MARKER,
  }));
  const encryptedItem = encrypt(vaultKey, plaintextItem, itemIv);
  const app = createApp({ dbPool: pool });

  try {
    const registration = await request(app).post('/api/auth/register').send({
      email,
      kdfSalt: base64(crypto.randomBytes(16)),
      kdfIterations: 600000,
      authHash: base64(authHash),
      wrappedVaultKey: base64(wrappedVaultKey),
      wrapIv: base64(wrapIv),
    });
    assert.equal(registration.status, 201);

    const login = await request(app).post('/api/auth/login').send({
      email,
      authHash: base64(authHash),
    });
    assert.equal(login.status, 200);

    const created = await request(app)
      .post('/api/vault')
      .set('Cookie', login.headers['set-cookie'])
      .send({ iv: base64(itemIv), ciphertext: base64(encryptedItem) });
    assert.equal(created.status, 201);

    const [users, items] = await Promise.all([
      pool.query('SELECT * FROM users WHERE email = $1', [email]),
      pool.query(
        'SELECT * FROM vault_items WHERE user_id = (SELECT id FROM users WHERE email = $1)',
        [email],
      ),
    ]);
    const databaseDump = JSON.stringify([...users.rows, ...items.rows]);
    assert.equal(databaseDump.includes(MARKER), false);
  } finally {
    await pool.query('DELETE FROM users WHERE email = $1', [email]);
    await closeDatabase();
  }
});