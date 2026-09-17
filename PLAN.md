# Plan de Proyecto: Gestor de Contraseñas Zero-Knowledge

## Cómo usar este documento

Pega este documento completo como contexto inicial a tu agente de IA (Claude Code, Cursor, etc.). Después, avanza **fase por fase**: pide al agente que implemente una fase, revisa el resultado, corre los criterios de aceptación de esa fase, y solo entonces pasa a la siguiente. No le pidas todo el proyecto de una vez — el diseño criptográfico es fácil de romper por prisa.

Al final de cada fase hay un prompt sugerido, listo para copiar y pegar.

---

## 0. Reglas generales para el agente (pégalas también, valen para todas las fases)

- Nunca transmitas ni loguees la contraseña maestra, la Master Key ni la Encryption Key. Solo el Auth Hash y datos ya cifrados viajan por la red.
- Todo número aleatorio criptográfico se genera con `crypto.getRandomValues` (navegador) o `crypto.randomBytes` (Node). Nunca `Math.random()`.
- Cada operación de cifrado AES-GCM usa un IV nuevo de 12 bytes. Nunca reutilizar un IV con la misma clave.
- El servidor no debe tener ninguna ruta de código que reciba, derive o procese contraseñas en texto plano ni claves de cifrado.
- Todas las comparaciones de secretos usan tiempo constante (`crypto.timingSafeEqual` o el comparador que ya trae `argon2`/`bcrypt`).
- Prioriza claridad sobre elegancia: este es un proyecto de aprendizaje, comenta el código explicando el *porqué* de cada decisión criptográfica.

---

## 1. Stack tecnológico

| Capa | Tecnología elegida | Por qué esta y no otra |
|---|---|---|
| Base de datos | **SQLite** vía `better-sqlite3` | Un solo archivo, API síncrona, cero configuración de servidor. Evita la complejidad de Postgres/Prisma sin sacrificar SQL real. |
| Backend | **Node.js + Express.js** | Pedido en el enunciado. Mínimo boilerplate. |
| Hash servidor del Auth Hash | **argon2** (paquete npm) — alternativa: **bcryptjs** si da problemas de compilación nativa | Segunda capa de hashing independiente de la derivación del cliente. |
| Frontend | **Vanilla JS/TypeScript + Vite** | Te obliga a tocar la Web Crypto API directamente sin que un framework la esconda. Si ya dominas React, es intercambiable sin cambiar el resto del plan. |
| Derivación de claves (cliente) | **PBKDF2-SHA256** vía `crypto.subtle` nativo | Evita instalar Argon2 en WASM en el navegador. Sube a Argon2id (con `hash-wasm`) como mejora opcional en la Fase 7 si quieres más puntos de innovación. |
| Cifrado de datos | **AES-GCM 256** vía `crypto.subtle` nativo | Nativo del navegador, autenticado (integridad + confidencialidad). |
| Separación de claves | **HKDF** vía `crypto.subtle` nativo | Deriva Encryption Key y Auth Hash del mismo Master Key sin que uno revele el otro. |
| Sesión | **Cookie httpOnly + JWT** (`jsonwebtoken`) | Evita que un XSS pueda robar el token desde `localStorage`. |
| Seguridad HTTP | **helmet**, **express-rate-limit**, **cors** | CSP, límite de intentos de login, control de origen. |
| Validación | **zod** | Verifica forma (base64, tamaños) sin nunca interpretar contenido. |
| Tests | **Vitest** o `node:test` | Unitarios para crypto + vectores NIST, e2e para el flujo completo. |
| Auditoría MitM | **mitmproxy** | Herramienta externa para capturar tráfico y demostrar ausencia de texto plano. |

---

## 2. Estructura de carpetas

```
password-manager-zk/
├── server/
│   ├── src/
│   │   ├── db.js              # conexión SQLite + schema
│   │   ├── routes/
│   │   │   ├── auth.js        # register, salt, login, logout
│   │   │   └── vault.js       # CRUD de blobs cifrados
│   │   ├── middleware/
│   │   │   └── requireAuth.js
│   │   └── app.js
│   ├── data/app.db             # archivo SQLite (gitignore)
│   ├── tests/
│   │   ├── crypto-vectors.test.js
│   │   └── zero-knowledge-audit.test.js   # revisa la DB en crudo
│   └── package.json
├── client/
│   ├── src/
│   │   ├── crypto/
│   │   │   ├── kdf.js          # deriveMasterKey, deriveSubkeys (HKDF)
│   │   │   ├── vault-key.js    # wrap/unwrap
│   │   │   └── cipher.js       # encryptItem/decryptItem
│   │   ├── api.js
│   │   └── main.js
│   └── package.json
└── PLAN.md                     # este archivo
```

---

## 3. Esquema de base de datos (SQLite)

```sql
CREATE TABLE users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  email               TEXT UNIQUE NOT NULL,
  kdf_salt            TEXT NOT NULL,       -- base64, generado en el CLIENTE
  kdf_iterations      INTEGER NOT NULL,    -- ej. 600000
  auth_hash_hashed    TEXT NOT NULL,       -- argon2(authHash del cliente)
  wrapped_vault_key   TEXT NOT NULL,       -- base64, AES-GCM(vaultKey)
  wrap_iv             TEXT NOT NULL,       -- base64, 12 bytes
  created_at          TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vault_items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  iv          TEXT NOT NULL,   -- base64, 12 bytes, único por item
  ciphertext  TEXT NOT NULL,   -- base64
  created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at  TEXT DEFAULT CURRENT_TIMESTAMP
);
```

Nota deliberada: ningún campo de esta base de datos, mirado directamente con `sqlite3 data/app.db "SELECT * FROM vault_items"`, debe permitir deducir nada sobre el contenido real.

---

## 4. Especificación de la API

| Método | Ruta | Body | Auth | Devuelve |
|---|---|---|---|---|
| POST | `/api/auth/register` | `{email, kdfSalt, kdfIterations, authHash, wrappedVaultKey, wrapIv}` | No | `201` |
| GET | `/api/auth/salt?email=` | — | No (rate-limited fuerte) | `{kdfSalt, kdfIterations}` |
| POST | `/api/auth/login` | `{email, authHash}` | No | Cookie httpOnly + `{wrappedVaultKey, wrapIv}` |
| POST | `/api/auth/logout` | — | Sí | `204` |
| GET | `/api/vault` | — | Sí | `[{id, iv, ciphertext, createdAt}]` |
| POST | `/api/vault` | `{iv, ciphertext}` | Sí | `{id}` |
| PUT | `/api/vault/:id` | `{iv, ciphertext}` | Sí | `204` |
| DELETE | `/api/vault/:id` | — | Sí | `204` |

Importante: el registro genera el salt **en el cliente**, no en el servidor. Así el servidor jamás produce material criptográfico, solo lo almacena. Para `GET /api/auth/salt`, considera devolver un salt "falso" pero determinístico (HMAC del email con un secreto del servidor) cuando el email no existe, para no filtrar qué emails están registrados.

---

## 5. Especificación criptográfica exacta

**Parámetros:**
- PBKDF2-SHA256, 600.000 iteraciones, salt de 16 bytes.
- HKDF-SHA256 para separar `encryptionKey` (info=`"enc"`) y `authKeyMaterial` (info=`"auth"`), 256 bits cada una.
- AES-GCM 256 bits, IV de 12 bytes aleatorio por operación, tag de 128 bits.
- Vault Key: 256 bits aleatorios, generada una sola vez en el registro.

**Registro (todo en el cliente antes de la petición HTTP):**
1. `masterKey = PBKDF2(masterPassword, salt, 600000)`
2. `encryptionKey, authKeyMaterial = HKDF(masterKey, info=["enc","auth"])`
3. `authHash = base64(authKeyMaterial)` → esto es lo único que ve el servidor.
4. `vaultKey = random(32 bytes)`
5. `wrapIv = random(12 bytes)`; `wrappedVaultKey = AES-GCM-encrypt(encryptionKey, wrapIv, vaultKey)`
6. POST a `/api/auth/register` con `{email, kdfSalt: salt, kdfIterations, authHash, wrappedVaultKey, wrapIv}`

**Login:**
1. `GET /api/auth/salt?email=` → `{kdfSalt, kdfIterations}`
2. Repetir pasos 1-3 del registro con el salt recibido.
3. `POST /api/auth/login {email, authHash}` → servidor verifica con `argon2.verify`, responde con cookie de sesión + `{wrappedVaultKey, wrapIv}`.
4. Cliente desenvuelve: `vaultKey = AES-GCM-decrypt(encryptionKey, wrapIv, wrappedVaultKey)`. Esta clave vive solo en memoria (variable JS, nunca `localStorage`).

**Guardar un item:**
1. `iv = random(12 bytes)`
2. `ciphertext = AES-GCM-encrypt(vaultKey, iv, JSON.stringify(entry))`
3. `POST /api/vault {iv, ciphertext}`

**Leer items:** `GET /api/vault`, luego `AES-GCM-decrypt(vaultKey, iv, ciphertext)` por cada uno, en el cliente.

---

## 6. Plan de fases

### Fase 0 — Scaffolding
**Tareas:** estructura de carpetas, `package.json` en server y client, Vite configurado, Express con endpoint `/health`, conexión a SQLite y creación de tablas si no existen.
**Criterio de aceptación:** `npm run dev` en ambas carpetas levanta sin errores; `/health` responde 200.

> **Prompt:** "Crea el scaffolding descrito en la sección 2 del plan. Backend con Express + better-sqlite3 aplicando el schema de la sección 3 al arrancar. Frontend con Vite + TypeScript vanilla. Solo un endpoint `/health`. No implementes todavía lógica de autenticación ni cifrado."

### Fase 1 — Módulo de criptografía del cliente (aislado, sin UI)
**Tareas:** implementar `kdf.js` (PBKDF2 + HKDF), `vault-key.js` (wrap/unwrap), `cipher.js` (encrypt/decrypt de items). Todo con `crypto.subtle`.
**Criterio de aceptación:** tests unitarios que cifran y descifran un objeto de prueba y recuperan el mismo contenido; test que verifica que dos cifrados del mismo texto con el mismo IV forzado (solo en test) producen el mismo ciphertext, y con IVs distintos producen ciphertexts distintos.

> **Prompt:** "Implementa el flujo criptográfico de la sección 5, exclusivamente en `client/src/crypto/`, sin ninguna llamada de red todavía. Usa `crypto.subtle` nativo. Escribe tests con Vitest para cada función."

### Fase 2 — Backend: registro y login
**Tareas:** rutas `auth.js`, `argon2` para rehash del authHash, JWT en cookie httpOnly, rate limiting en `/api/auth/login` y `/api/auth/salt`.
**Criterio de aceptación:** con Postman/curl, registrar un usuario y hacer login funciona; 6 intentos fallidos de login bloquean temporalmente.

> **Prompt:** "Implementa `/api/auth/register`, `/api/auth/salt` y `/api/auth/login` según la sección 4. Usa argon2 para rehashear el authHash antes de guardarlo. Sesión vía cookie httpOnly + JWT firmado. Rate limit de 5 intentos por 15 minutos en login."

### Fase 3 — Frontend: registro y login conectados
**Tareas:** formularios simples, integrar los módulos de crypto de la Fase 1 con las llamadas HTTP.
**Criterio de aceptación:** flujo completo manual: registrar usuario nuevo → cerrar pestaña → volver a abrir → login exitoso → `vaultKey` recuperada en memoria (verificable con un `console.log` temporal que se retira después).

> **Prompt:** "Conecta el módulo de crypto con la UI de registro y login. Después del login, guarda la `vaultKey` en una variable de módulo en memoria, nunca en localStorage ni sessionStorage."

### Fase 4 — CRUD de la bóveda
**Tareas:** backend `/api/vault` completo con `requireAuth` middleware; frontend con lista de credenciales, formulario para añadir/editar/borrar.
**Criterio de aceptación:** crear, ver, editar y borrar una credencial funciona de punta a punta; un usuario no puede ver ni borrar items de otro usuario (probarlo con dos cuentas).

> **Prompt:** "Implementa el CRUD completo de `/api/vault` con el middleware `requireAuth` que verifica que `user_id` del recurso coincide con el usuario de la sesión. En el frontend, construye la UI de la bóveda usando `cipher.js` para cifrar antes de enviar y descifrar al recibir."

### Fase 5 — Endurecimiento de seguridad backend
**Tareas:** `helmet` con CSP estricta (sin `unsafe-inline`), `cors` limitado a tu origen, `zod` validando forma de los payloads (base64, longitud máxima).
**Criterio de aceptación:** headers de seguridad presentes en la respuesta (verificar con `curl -I`); una petición con un campo malformado devuelve 400, no 500.

> **Prompt:** "Añade helmet con una CSP estricta (default-src 'self', sin unsafe-inline ni unsafe-eval), cors limitado al origen del frontend, y valida con zod que iv y ciphertext son base64 válido con un tamaño máximo razonable."

### Fase 6 — Vectores de prueba NIST
**Tareas:** test que alimenta las funciones de PBKDF2 y AES-GCM con vectores oficiales del NIST y compara byte a byte.
**Criterio de aceptación:** los tests pasan contra los vectores conocidos, no solo contra datos generados por el propio código (evita el falso positivo de "cifra y descifra consistentemente pero mal").

> **Prompt:** "Busca los vectores de prueba oficiales del NIST para PBKDF2-HMAC-SHA256 y AES-256-GCM, y escribe tests que verifiquen que nuestras funciones producen exactamente esos outputs conocidos."

### Fase 7 — Auditoría "Modo Difícil"
**Tareas:**
- Script `zero-knowledge-audit.test.js`: hace login/registro/creación de items de prueba con contenido reconocible (ej. `"CONTRASEÑA_DE_PRUEBA_XYZ"`), luego lee la base SQLite directamente con `better-sqlite3` y falla el test si encuentra esa cadena en cualquier columna de cualquier tabla.
- Instrucciones para correr `mitmproxy` en modo reverse proxy delante del backend, usar la app a través de él, y confirmar visualmente que ningún payload capturado contiene texto plano de contraseñas maestras ni claves.
- Documentar por escrito la limitación estructural: el servidor sirve el JavaScript que cifra, así que un servidor comprometido podría alterar ese código. Mitigado parcialmente con CSP + Subresource Integrity (SRI) en los bundles.

**Criterio de aceptación:** el test automatizado de la DB pasa; capturas de mitmproxy adjuntas al informe mostrando solo blobs base64 ininteligibles.

> **Prompt:** "Escribe `zero-knowledge-audit.test.js`: crea un usuario y un item de vault con el texto literal 'CONTRASEÑA_DE_PRUEBA_XYZ', luego abre `data/app.db` directamente con better-sqlite3 y falla el test si esa cadena aparece en cualquier fila de cualquier tabla. Además, añade Subresource Integrity a los scripts del build de Vite."

### Fase 8 — Pulido y documentación
**Tareas:** README con instrucciones de instalación, diagrama del flujo criptográfico, sección de "amenazas conocidas y no mitigadas" (honestidad técnica).
**Criterio de aceptación:** alguien que no conoce el proyecto puede clonarlo, instalarlo y correrlo siguiendo solo el README.

---

## 7. Checklist final antes de entregar

- [ ] Ningún endpoint recibe contraseña maestra ni clave de cifrado en texto plano.
- [ ] `SELECT * FROM users` y `SELECT * FROM vault_items` no revelan nada legible.
- [ ] IVs nunca se reutilizan (verificado por test).
- [ ] Auth Hash y Encryption Key derivan de contextos HKDF distintos.
- [ ] Rate limiting activo en login.
- [ ] CSP sin `unsafe-inline`/`unsafe-eval`.
- [ ] Cookie de sesión `httpOnly`, `Secure`, `SameSite=Strict`.
- [ ] Vectores NIST pasando.
- [ ] Captura de mitmproxy documentada.
- [ ] Sección de limitaciones conocidas escrita en el README (código entregado por el servidor).

