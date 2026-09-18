# Gestor de contrasenas Zero-Knowledge

Scaffolding inicial de un gestor de contrasenas con arquitectura split-key.
La implementacion avanza por fases segun [PLAN.md](PLAN.md).

## Requisitos

- Node.js 20 o superior
- npm

## Backend

```bash
cd server
npm install
npm run dev
```

El servidor queda disponible en `http://localhost:3000`. La comprobacion de
salud responde en `http://localhost:3000/health`.

La primera ejecucion crea `server/data/app.db` y las tablas base de SQLite.
La base local esta excluida de Git.

## Cliente

En otra terminal:

```bash
cd client
npm install
npm run dev
```

Vite mostrara la URL local del cliente, normalmente `http://localhost:5173`.

