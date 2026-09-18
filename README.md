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
```

## Cliente

En otra terminal:

```bash
cd client
npm install
npm run dev
```

Vite mostrara la URL local del cliente, normalmente `http://localhost:5173`.

