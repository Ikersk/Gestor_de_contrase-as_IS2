# Arca — Gestor de contraseñas Zero-Knowledge

Gestor de contraseñas con arquitectura split-key y persistencia PostgreSQL en Supabase. La criptografía se ejecuta enteramente en el navegador; el servidor almacena material derivado y blobs cifrados sin nunca ver contraseñas ni claves en texto plano.

## Requisitos

- Node.js 20 o superior
- npm
- Un proyecto PostgreSQL en Supabase

## Instalación

### 1. Backend

```bash
cd server
npm install
```

### 2. Configuración

Crea `server/.env` desde `server/.env.example` y completa la cadena de conexión:

```env
DATABASE_URL=postgresql://postgres:TU_PASSWORD@db.TU_PROJECT_REF.supabase.co:5432/postgres
DB_SSL=true
DB_SSL_REJECT_UNAUTHORIZED=false
JWT_SECRET=una-clave-aleatoria-de-al-menos-32-caracteres
COOKIE_SECURE=false
FRONTEND_ORIGIN=http://localhost:5173
```

> **Importante:** En desarrollo sobre `http://localhost`, `COOKIE_SECURE=false` es necesario para que el navegador envíe la cookie de sesión sin HTTPS. En producción debe mantenerse en `true`.

### 3. Base de datos

```bash
npm run db:check    # verifica la conexión a PostgreSQL
npm run db:migrate  # crea las tablas users y vault_items (idempotente)
```

### 4. Arrancar el servidor

```bash
npm run dev
```

El servidor queda disponible en `http://localhost:3000`. El endpoint `/health` comprueba la conexión a PostgreSQL.

### 5. Frontend

En otra terminal:

```bash
cd client
npm install
npm run dev
```

Vite mostrará la URL local del cliente (normalmente `http://localhost:5173`). El proxy de Vite redirige `/api` al backend en `http://localhost:3000`.

## Features

### Seguridad

- **Zero-Knowledge**: la contraseña maestra nunca sale del navegador. El servidor solo recibe material derivado (authHash) y blobs cifrados.
- **PBKDF2-SHA256** (600K iteraciones, salt 16 bytes) para derivación de la Master Key.
- **HKDF-SHA256** para separar Encryption Key y Auth Hash de contextos independientes.
- **AES-GCM-256** (IV 12 bytes único por operación) para cifrar la Vault Key y cada credencial.
- **Vault Key** de 256 bits generada una vez en el registro, nunca almacenada en texto plano.
- **bcryptjs** (cost 12) para hashing del authHash en servidor.
- **JWT** HS256 en cookie httpOnly, Secure, SameSite=Strict (8 horas).
- **Rate limiting** (5 intentos/15min) en login, cambio de contraseña y eliminación de cuenta.
- **CSP** estricta via Helmet (sin unsafe-inline/eval).
- **CORS** restringido a FRONTEND_ORIGIN.
- **Vectores NIST** verificados byte a byte para PBKDF2 y AES-GCM.

### Funcionalidad

- **Bóveda de credenciales**: crear, editar, eliminar credenciales cifradas con split-pane layout (lista + detalle).
- **Generador de contraseñas**: aleatoriedad criptográfica (`crypto.getRandomValues`) con rejection sampling.
- **TOTP/2FA**: generación de códigos TOTP para credenciales que lo requieran.
- **Detección de brechas (HIBP)**: verificación automática de contraseñas comprometidas usando k-Anonymity. Se ejecuta al desbloquear la bóveda.
- **Security Dashboard**: métricas de salud, credenciales, alertas y brechas HIBP.
- **Cambio de contraseña maestra**: re-derivación de claves y re-envoltura de la Vault Key sin modificar ciphertexts existentes.
- **Eliminación de cuenta**: eliminación permanente de todos los datos cifrados.
- **Theme Switcher**: modo oscuro/claro con persistencia en localStorage.
- **Landing page**: presentación del proyecto con arquitectura, FAQ y CTA.
- **Toast Notifications**: confirmaciones y errores en notificaciones efímeras.

## Límites de campos

| Campo | Longitud máxima | Notas |
|---|---|---|
| Email | 40 caracteres | Formato válido obligatorio |
| Contraseña maestra | 42 caracteres | Mínimo 12 caracteres |
| Nombre de credencial | 30 caracteres | Al menos una letra |
| Usuario de credencial | 30 caracteres | Al menos una letra |
| Contraseña de credencial | 32 caracteres | — |
| URL | 100 caracteres | http/https, máximo 8 URLs por credencial |
| Secreto TOTP | 128 caracteres | Base32 |
| Cuerpo JSON servidor | 2 MB | Límite de Express |

## Pruebas y auditoría

```bash
# Servidor (node:test + supertest)
cd server
npm test

# Cliente (Vitest)
cd client
npm test
npm run build
```

El build genera automáticamente hashes SRI SHA-384 en `dist/index.html` para los bundles JavaScript y CSS.

### Auditoría de base de datos

Abre el **SQL Editor** de Supabase y ejecuta:

```sql
SELECT * FROM users;
SELECT * FROM vault_items;
```

En `users` deben aparecer hashes bcrypt, salt, iteraciones, `wrapped_vault_key` y `wrap_iv`. En `vault_items` únicamente `iv` y `ciphertext`. Todos los valores deben ser hashes o cadenas Base64 ilegibles; no deben aparecer contraseñas, usuarios ni URLs en texto plano.

### Auditoría de tráfico

Abre DevTools → **Network** y usa la aplicación. En las peticiones de registro, login y vault deben aparecer únicamente material derivado, IVs y blobs Base64; nunca la contraseña maestra, la Vault Key ni los campos legibles de una credencial.

## Documentación adicional

- [PLAN.md](PLAN.md) — plan del proyecto, especificación criptográfica y fases.
- [FLUJO.md](FLUJO.md) — descripción detallada de cada flujo de datos.
- [DOCS.md](DOCS.md) — documentación técnica y decisiones arquitectónicas.
