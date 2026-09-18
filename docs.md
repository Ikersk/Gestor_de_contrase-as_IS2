# Documentacion tecnica

## Estado actual

Este proyecto es un gestor de contrasenas Zero-Knowledge con arquitectura
split-key. El cliente React/Vite ejecuta la derivacion y el cifrado; el
servidor Express solo debe recibir hashes de autenticacion y datos cifrados.

Completado hasta ahora:

- Scaffolding de backend Express y cliente React/Vite/TypeScript.
- Migracion de SQLite a PostgreSQL gestionado por Supabase mediante `pg`.
- Migracion SQL idempotente en `server/sql/001_initial_schema.sql`.
- Tablas `users` y `vault_items` con relacion por `user_id`.
- RLS habilitado en ambas tablas.
- Endpoint `GET /health` conectado a PostgreSQL.
- Modulo crypto del cliente con PBKDF2-SHA256, HKDF-SHA256 y AES-GCM-256.
- Envoltura y desenvoltura de `vaultKey`.
- Tests Vitest para derivacion, wrap/unwrap y cifrado.

## Estructura importante

```text
server/
  src/app.js                         # Express, /health y arranque
  src/db.js                          # Pool PostgreSQL
  src/migrate.js                     # Comandos de conexion y migracion
  sql/001_initial_schema.sql         # Schema PostgreSQL y RLS
  .env.example                       # Variables sin secretos

client/
  src/crypto/kdf.js                  # PBKDF2, HKDF, base64 y aleatoriedad
  src/crypto/vault-key.js            # Vault key con AES-GCM
  src/crypto/cipher.js               # Cifrado de items JSON
  src/crypto/crypto.test.js          # Tests de crypto
```

## Supabase y variables de entorno

El secreto real vive en `server/.env` y esta excluido por `.gitignore`.
Nunca debe subirse al repositorio.

```env
PORT=3000
DATABASE_URL=postgresql://postgres:TU_PASSWORD@db.TU_PROJECT_REF.supabase.co:5432/postgres
DB_SSL=true
DB_SSL_REJECT_UNAUTHORIZED=false
DB_POOL_MAX=10
```

`DB_SSL_REJECT_UNAUTHORIZED=false` facilita la conexion inicial. En
produccion conviene usar el certificado CA de Supabase y mantener la
verificacion TLS activada.

## Comandos

Backend, desde `server/`:

```bash
npm install
npm run db:check
npm run db:migrate
npm run dev
```

El endpoint de comprobacion es:

```bash
curl http://localhost:3000/health
```

Respuesta esperada:

```json
{"status":"ok"}
```

Cliente, desde `client/`:

```bash
npm install
npm test
npm run build
npm run dev
```

## Seguridad implementada

- La aleatoriedad del navegador usa `crypto.getRandomValues`.
- AES-GCM utiliza IVs de 12 bytes y claves de 256 bits.
- PBKDF2 usa SHA-256 y 600000 iteraciones por defecto.
- HKDF separa los contextos `enc` y `auth`.
- La `vaultKey` no se guarda en `localStorage` ni `sessionStorage`.
- React no se conecta directamente a Supabase.
- RLS esta activado para `users` y `vault_items`.
- No se registran contrasenas maestras ni claves de cifrado.

## Trabajo pendiente

Segun `PLAN.md`, aun falta implementar:

1. Fase 2: registro, consulta de salt, login, Argon2, JWT, cookie httpOnly y rate limiting.
2. Fase 3: formularios de registro/login conectados al modulo crypto.
3. Fase 4: CRUD de la boveda y middleware `requireAuth`.
4. Fase 5: Helmet, CSP, CORS y validacion Zod.
5. Fase 6: vectores oficiales NIST.
6. Fase 7: auditoria Zero-Knowledge, mitmproxy y SRI.
7. Fase 8: documentacion final, diagrama y amenazas conocidas.

Actualmente no existen aun las rutas `/api/auth` ni `/api/vault`. No deben
implementarse saltandose el orden del plan.

## Continuacion recomendada

La siguiente tarea es la Fase 2. El servidor debe recibir unicamente:

- `email`.
- `kdfSalt` y `kdfIterations` generados por el cliente.
- `authHash` derivado por el cliente, que se volvera a hashear con Argon2.
- `wrappedVaultKey` y `wrapIv`.

La contrasena maestra, la Master Key, la Encryption Key y la `vaultKey` nunca
deben llegar al servidor ni almacenarse en texto plano.
