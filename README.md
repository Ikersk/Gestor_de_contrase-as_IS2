# Gestor de contrasenas Zero-Knowledge

Gestor de contrasenas con arquitectura split-key y persistencia PostgreSQL en Supabase.
La implementacion avanza por fases segun [PLAN.md](PLAN.md).

## Requisitos

- Node.js 20 o superior
- npm
- Un proyecto PostgreSQL en Supabase

## Backend

```bash
cd server
npm install
npm run db:check
npm run db:migrate
npm run dev
```

Antes de arrancar, crea `server/.env` desde `server/.env.example` y completa
la cadena de conexion de Supabase. El servidor queda disponible en
`http://localhost:3000`; `/health` comprueba tambien la conexion PostgreSQL.

`npm run db:migrate` crea las tablas `users` y `vault_items` de forma
idempotente. Nunca subas `server/.env` ni una contrasena real al repositorio.

Ejemplo de configuracion:

```env
DATABASE_URL=postgresql://postgres:TU_PASSWORD@db.TU_PROJECT_REF.supabase.co:5432/postgres
DB_SSL=true
DB_SSL_REJECT_UNAUTHORIZED=false
JWT_SECRET=una-clave-aleatoria-de-al-menos-32-caracteres
COOKIE_SECURE=false
FRONTEND_ORIGIN=http://localhost:5173
```

En desarrollo sobre `http://localhost`, `COOKIE_SECURE=false` permite que el
navegador envie la cookie de sesion. En produccion debe mantenerse en `true`.
`FRONTEND_ORIGIN` limita CORS al origen exacto del cliente y permite
credenciales para la cookie de sesion. El backend tambien envia una CSP estricta
mediante Helmet.

Los formularios limitan el correo a 40 caracteres, la contrasena maestra a 42,
el nombre de credencial a 30, el usuario a 30, la contrasena guardada a 32 y la
URL a 100. Nombre y usuario deben contener al menos una letra. Las credenciales
se validan en el cliente antes de cifrarse; el backend limita ademas el cuerpo
JSON y los blobs cifrados.

El cliente deriva las claves localmente durante el registro y el login. La
contrasena maestra nunca se envia al backend ni se guarda en `localStorage` o
`sessionStorage`; la `vaultKey` solo vive en memoria mientras la sesion esta
abierta.

Con la sesion abierta puedes crear, editar y borrar credenciales desde la
interfaz. Cada item se cifra en el cliente antes de enviarse a `/api/vault`.

## Cliente

En otra terminal:

```bash
cd client
npm install
npm run dev
```

Vite mostrara la URL local del cliente, normalmente `http://localhost:5173`.

## Pruebas y auditoria

Ejecuta las pruebas normales sin tocar la base de datos real:

```bash
cd server
npm test

cd ../client
npm test -- --run
npm run build
```

El build genera automaticamente hashes SRI SHA-384 en `dist/index.html` para
los bundles JavaScript y CSS.

La auditoria Zero-Knowledge usa la base PostgreSQL configurada en `server/.env`.
Crea una cuenta temporal, cifra un marcador reconocible en el navegador
simulado, busca ese marcador en las filas de `users` y `vault_items`, y limpia
la cuenta al terminar. Ejecutala solo contra una base de pruebas:

```bash
cd server
npm run test:audit
```

## Captura con mitmproxy

Para inspeccionar el tráfico HTTP local sin modificar la aplicación:

```bash
mitmweb --mode reverse:http://localhost:3000@3001
```

Configura temporalmente `VITE_API_BASE_URL=http://localhost:3001/api`, inicia
el cliente y usa la interfaz a través del puerto `3001`. En las peticiones de
registro, login y vault deben aparecer únicamente material derivado, IVs y
blobs Base64; nunca la contraseña maestra, la Vault Key ni los campos legibles
de una credencial. No adjuntes certificados ni capturas con secretos reales.

## Flujo criptografico

```mermaid
flowchart LR
	P[Contrasena maestra] --> K[PBKDF2-SHA256]
	S[Salt del cliente] --> K
	K --> M[Master Key]
	M --> H[HKDF info auth]
	M --> E[HKDF info enc]
	H --> A[Auth Hash]
	E --> W[AES-GCM envuelve Vault Key]
	A --> R[Servidor: bcrypt + JWT]
	W --> R
	V[Credencial legible] --> C[AES-GCM con Vault Key]
	C --> B[IV + ciphertext Base64]
	B --> R
```

## Amenazas conocidas

- Un servidor comprometido podría entregar JavaScript modificado antes de que
	el navegador cifre una credencial. CSP y SRI reducen cambios accidentales o
	recursos externos, pero no sustituyen servir el cliente desde un canal y una
	cadena de despliegue confiables.
- El servidor puede observar metadatos como email, tamaños aproximados,
	timestamps y frecuencia de acceso, aunque no descifre los blobs.
- La pérdida de la contraseña maestra implica la pérdida de la capacidad de
	desenvolver la Vault Key; no existe recuperación por diseño zero-knowledge.
- XSS en el origen de la aplicación podría acceder a secretos mientras la
	bóveda está desbloqueada. La CSP estricta ayuda, pero las dependencias y el
	servidor de frontend siguen formando parte del perímetro de confianza.
- mitmproxy solo demuestra el tráfico de la ejecución inspeccionada; no prueba
	todos los despliegues ni sustituye una revisión del código entregado.

