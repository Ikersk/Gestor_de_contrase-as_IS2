require('dotenv').config();

// CLI de mantenimiento: crea cuentas de prueba con credenciales de ejemplo.
// Idempotente: si el email ya existe se omite la cuenta completa (no borra ni modifica nada).
// Reproduce la misma cadena KDF/cifrado que el cliente para que el login real funcione.
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { checkDatabaseConnection, closeDatabase, initializeDatabase, pool } = require('./db');

const MASTER_PASSWORD = 'TestMaster1234!';
const KDF_ITERATIONS = 600_000;
const KDF_SALT_BYTES = 16;
const AES_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const BCRYPT_COST = 12;

// ── KDF y cifrado (equivalente Node a client/src/crypto/*.js) ──

/** Master Key = PBKDF2-SHA256(password, salt, iteraciones) → 32 bytes. */
function deriveMasterKey(password, salt, iterations) {
  return crypto.pbkdf2Sync(password, salt, iterations, AES_KEY_BYTES, 'sha256');
}

/** HKDF-SHA256 con salt vacío y los mismos info strings que el cliente ("enc"/"auth"). */
function deriveHkdf(masterKey, info) {
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), info, AES_KEY_BYTES));
}

/** AES-256-GCM: devuelve ciphertext || tag(16) como Web Crypto (tagLength 128). */
function aesGcmEncrypt(key, iv, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([encrypted, cipher.getAuthTag()]);
}

/** AES-256-GCM de descifrado (tag incluido al final del ciphertext). */
function aesGcmDecrypt(key, iv, ciphertextWithTag) {
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const data = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ── Datos de prueba ──

const TEST_ACCOUNTS = [
  {
    email: 'test01@demo.test',
    credentials: [
      { title: 'Correo personal', username: 'test01@demo.test', password: 'DemoMail#01x9', urls: ['https://mail.demo.test'], favorite: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
      { title: 'GitHub', username: 'demo-test-01', password: 'Gh-Demo-01!abc', urls: ['https://github.com'], favorite: false },
      { title: 'Netflix', username: 'test01@demo.test', password: 'Ntf-2024-Demo01', urls: ['https://netflix.com'], favorite: false },
      { title: 'Spotify', username: 'test01@demo.test', password: 'Spt-Demo-01!ab', urls: ['https://spotify.com'], favorite: false },
      { title: 'LinkedIn', username: 'test01@demo.test', password: 'Li-Demo-01!cd', urls: ['https://linkedin.com'], favorite: false },
      { title: 'Amazon', username: 'test01@demo.test', password: 'Amz-Demo-01#ef', urls: ['https://amazon.com'], favorite: false },
      { title: 'PayPal', username: 'test01@demo.test', password: 'Pp-Demo-01#gh', urls: ['https://paypal.com'], favorite: false, totpSecret: 'MZXW6YTBOI======', },
      { title: 'Discord', username: 'demo_user_01', password: 'Dsc-Demo-01!ij', urls: ['https://discord.com'], favorite: false },
      { title: 'Reddit', username: 'demo_test_01', password: 'Rdt-Demo-01!kl', urls: ['https://reddit.com'], favorite: false },
      { title: 'Twitch', username: 'demo_stream_01', password: 'Twt-Demo-01!mn', urls: ['https://twitch.tv'], favorite: false },
      { title: 'Figma', username: 'test01@demo.test', password: 'Fgm-Demo-01#op', urls: ['https://figma.com'], favorite: false },
      { title: 'Notion', username: 'test01@demo.test', password: 'Not-Demo-01!qr', urls: ['https://notion.so'], favorite: false },
      { title: 'Dropbox', username: 'test01@demo.test', password: 'Dbx-Demo-01#st', urls: ['https://dropbox.com'], favorite: false },
    ],
  },
  {
    email: 'test02@demo.test',
    credentials: [
      { title: 'Correo trabajo', username: 'test02@demo.test', password: 'Work-Mail#02kL', urls: ['https://outlook.demo.test'], favorite: true },
      { title: 'Twitter / X', username: '@demo_test_02', password: 'X-Demo-02!xyz', urls: ['https://x.com'], favorite: false },
      { title: 'Dropbox', username: 'test02@demo.test', password: 'Dbx-2024-Demo02', urls: ['https://dropbox.com'], favorite: false },
      { title: 'Steam', username: 'demo_steam_02', password: 'Stm-Demo-02#qq', urls: ['https://store.steampowered.com'], favorite: false },
    ],
  },
  {
    email: 'test03@demo.test',
    credentials: [
      { title: 'Banco de prueba', username: 'demo-user-03', password: 'Bank-Demo#03Ab', urls: ['https://banco.demo.test'], favorite: true, totpSecret: 'KRSXG5CTMVRXEZLU' },
      { title: 'LinkedIn', username: 'test03@demo.test', password: 'Li-Demo-03!mn', urls: ['https://linkedin.com'], favorite: false },
      { title: 'Spotify', username: 'test03@demo.test', password: 'Spt-2024-Demo03', urls: ['https://spotify.com'], favorite: false },
    ],
  },
  {
    email: 'test04@demo.test',
    credentials: [
      { title: 'Instagram', username: '@demo.test04', password: 'Ig-Demo-04#pw', urls: ['https://instagram.com'], favorite: true },
      { title: 'Amazon', username: 'test04@demo.test', password: 'Amz-Demo-04!rt', urls: ['https://amazon.com'], favorite: false },
      { title: 'PayPal', username: 'test04@demo.test', password: 'Pp-Demo-04#vu', urls: ['https://paypal.com'], favorite: false, totpSecret: 'MZXW6YTBOI======' },
      { title: 'Discord', username: 'demo04', password: 'Dsc-2024-Demo04', urls: ['https://discord.com'], favorite: false },
      { title: 'Reddit', username: 'demo_test_04', password: 'Rdt-Demo-04!jk', urls: ['https://reddit.com'], favorite: false },
    ],
  },
  {
    email: 'test05@demo.test',
    credentials: [
      { title: 'Correo personal', username: 'test05@demo.test', password: 'DemoMail#05pQ', urls: ['https://mail.demo.test', 'https://webmail.demo.test'], favorite: true },
      { title: 'Figma', username: 'test05@demo.test', password: 'Figma-Demo#05', urls: ['https://figma.com'], favorite: false },
      { title: 'Notion', username: 'test05@demo.test', password: 'Not-2024-Demo05', urls: ['https://notion.so'], favorite: false },
    ],
  },
  {
    email: 'test06@demo.test',
    credentials: [
      { title: 'WhatsApp Web', username: '+34 600 000 006', password: 'Wa-Demo-06#ss', urls: ['https://web.whatsapp.com'], favorite: true },
      { title: 'Telegram', username: '@demo_test_06', password: 'Tg-Demo-06!dd', urls: ['https://web.telegram.org'], favorite: false },
      { title: 'Twitch', username: 'demo_stream_06', password: 'Twt-2024-Demo06', urls: ['https://twitch.tv'], favorite: false },
      { title: 'TikTok', username: '@demo.test06', password: 'Tk-Demo-06#ff', urls: ['https://tiktok.com'], favorite: false },
    ],
  },
  {
    email: 'test07@demo.test',
    credentials: [
      { title: 'Azure de prueba', username: 'demo.admin07', password: 'Az-Demo#07Wxyz', urls: ['https://portal.azure.com'], favorite: true, totpSecret: 'NBSWY3DPEB3W64TMMQ======' },
      { title: 'AWS Console', username: 'demo-root-07', password: 'Aws-Demo-07!aa', urls: ['https://aws.amazon.com'], favorite: false },
      { title: 'DigitalOcean', username: 'test07@demo.test', password: 'Do-2024-Demo07', urls: ['https://digitalocean.com'], favorite: false },
    ],
  },
  {
    email: 'test08@demo.test',
    credentials: [
      { title: 'Uber', username: 'test08@demo.test', password: 'Ub-Demo-08#nn', urls: ['https://uber.com'], favorite: false },
      { title: 'Airbnb', username: 'test08@demo.test', password: 'Ab-2024-Demo08', urls: ['https://airbnb.com'], favorite: true },
      { title: 'Booking', username: 'demo.travel08', password: 'Bk-Demo-08!bb', urls: ['https://booking.com'], favorite: false },
      { title: 'Renfe', username: 'demo-user-08', password: 'Rn-Demo-08#cc', urls: ['https://renfe.com'], favorite: false },
    ],
  },
  {
    email: 'test09@demo.test',
    credentials: [
      { title: 'MiWiFi router', username: 'admin', password: 'Router-Demo#09', urls: ['http://192.168.1.1'], favorite: false },
      { title: 'Home Assistant', username: 'demo09', password: 'Ha-Demo-09!home', urls: ['https://home-assistant.io'], favorite: true },
      { title: 'Nextcloud', username: 'test09@demo.test', password: 'Nc-2024-Demo09', urls: ['https://nextcloud.demo.test'], favorite: false },
    ],
  },
  {
    email: 'test10@demo.test',
    credentials: [
      { title: 'Cuenta principal', username: 'test10@demo.test', password: 'Main-Demo#10Zz', urls: ['https://example.com'], favorite: true, totpSecret: 'GEZDGNBVGY3TQOJQ' },
      { title: 'Foro universidad', username: 'demo_alumno10', password: 'U-FORO-Demo#10', urls: ['https://foro.demo.test'], favorite: false },
      { title: 'Wiki interna', username: 'test10@demo.test', password: 'Wiki-2024-Demo10', urls: ['https://wiki.demo.test'], favorite: false },
      { title: 'Pastebin', username: 'demo_pastebin', password: 'Pb-Demo-10!vv', urls: ['https://pastebin.com'], favorite: false },
    ],
  },
];

// ── Construcción de una cuenta ──

/** Deriva todo el material de una cuenta tal como lo haría el cliente en registro. */
function buildAccountMaterial(password) {
  const kdfSalt = crypto.randomBytes(KDF_SALT_BYTES);
  const masterKey = deriveMasterKey(password, kdfSalt, KDF_ITERATIONS);
  const encryptionKey = deriveHkdf(masterKey, 'enc');
  const authKeyMaterial = deriveHkdf(masterKey, 'auth');
  const authHash = authKeyMaterial.toString('base64');

  const vaultKey = crypto.randomBytes(AES_KEY_BYTES);
  const wrapIv = crypto.randomBytes(AES_GCM_IV_BYTES);
  const wrappedVaultKey = aesGcmEncrypt(encryptionKey, wrapIv, vaultKey);

  return {
    kdfSalt: kdfSalt.toString('base64'),
    kdfIterations: KDF_ITERATIONS,
    authHash,
    wrappedVaultKey: wrappedVaultKey.toString('base64'),
    wrapIv: wrapIv.toString('base64'),
    vaultKey,
    encryptionKey,
  };
}

/** Cifra una credencial con la Vault Key (mismo JSON normalizado que el cliente). */
function encryptCredential(vaultKey, credential) {
  const normalized = {
    title: credential.title,
    username: credential.username,
    password: credential.password,
    urls: credential.urls,
    favorite: Boolean(credential.favorite),
    ...(credential.totpSecret ? { totpSecret: credential.totpSecret } : {}),
  };
  const iv = crypto.randomBytes(AES_GCM_IV_BYTES);
  const ciphertext = aesGcmEncrypt(vaultKey, iv, Buffer.from(JSON.stringify(normalized), 'utf8'));
  return { iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64') };
}

// ── CLI principal ──

async function main() {
  await checkDatabaseConnection();
  await initializeDatabase();

  let created = 0;
  let skipped = 0;
  let itemsInserted = 0;

  for (const account of TEST_ACCOUNTS) {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [account.email]);
    if (existing.rowCount > 0) {
      console.log(`skip  ${account.email} (ya existe)`);
      skipped += 1;
      continue;
    }

    const material = buildAccountMaterial(MASTER_PASSWORD);
    // El server hashea el authHash en base64 con bcrypt cost 12 (igual que auth.js).
    const authHashHashed = await bcrypt.hash(material.authHash, BCRYPT_COST);

    const inserted = await pool.query(
      `INSERT INTO users (email, kdf_salt, kdf_iterations, auth_hash_hashed, wrapped_vault_key, wrap_iv)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [account.email, material.kdfSalt, material.kdfIterations, authHashHashed,
        material.wrappedVaultKey, material.wrapIv],
    );
    const userId = inserted.rows[0].id;

    for (const credential of account.credentials) {
      const { iv, ciphertext } = encryptCredential(material.vaultKey, credential);
      await pool.query(
        'INSERT INTO vault_items (user_id, iv, ciphertext) VALUES ($1, $2, $3)',
        [userId, iv, ciphertext],
      );
      itemsInserted += 1;
    }

    created += 1;
    console.log(`create ${account.email} (${account.credentials.length} credenciales)`);
  }

  console.log(`\nListo: ${created} creadas, ${skipped} omitidas, ${itemsInserted} credenciales insertadas.`);
  console.log(`Contraseña maestra común: ${MASTER_PASSWORD}`);
}

main()
  .catch((error) => {
    console.error('Seed failed:', error.message);
    process.exitCode = 1;
  })
  .finally(closeDatabase);
