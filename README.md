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
```

En desarrollo sobre `http://localhost`, `COOKIE_SECURE=false` permite que el
navegador envie la cookie de sesion. En produccion debe mantenerse en `true`.

El cliente deriva las claves localmente durante el registro y el login. La
contrasena maestra nunca se envia al backend ni se guarda en `localStorage` o
`sessionStorage`; la `vaultKey` solo vive en memoria mientras la sesion esta
abierta.

## Cliente

En otra terminal:

```bash
cd client
npm install
npm run dev
```

Vite mostrara la URL local del cliente, normalmente `http://localhost:5173`.

