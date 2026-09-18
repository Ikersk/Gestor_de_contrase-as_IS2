# Documentacion tecnica del proyecto

## 1. Resumen
Hasta ahora se han completado el scaffolding inicial, la persistencia PostgreSQL en Supabase y el modulo criptografico aislado del cliente.

## 2. Estado actual

### Implementado

- Backend Node.js + Express.
- Cliente React + Vite + TypeScript.
- PostgreSQL gestionado por Supabase mediante el paquete `pg`.
- Pool de conexiones PostgreSQL con SSL configurable.
- Migracion SQL idempotente para `users` y `vault_items`.
- RLS activado para ambas tablas.
- Endpoint `GET /health`.
- Comandos `db:check` y `db:migrate`.
- Criptografia del cliente con Web Crypto API:
  - PBKDF2-SHA256.
  - HKDF-SHA256.
  - AES-GCM de 256 bits.
  - Envoltura y desenvoltura de `vaultKey`.
  - Serializacion de items como JSON.
- Tests Vitest para el modulo criptografico.
- Pantalla inicial React sin llamadas de red ni persistencia de secretos.

### Pendiente

Las rutas de autenticacion y de la boveda todavia no existen. Esto es intencional: pertenecen a las fases siguientes del plan.

- Fase 2: registro, consulta de salt, login, Argon2, JWT, cookie httpOnly y rate limiting.
- Fase 3: formularios de registro/login conectados al modulo crypto.
- Fase 4: CRUD de la boveda y middleware `requireAuth`.
- Fase 5: Helmet, CSP estricta, CORS y Zod.
- Fase 6: vectores oficiales NIST.
- Fase 7: auditoria Zero-Knowledge, mitmproxy y SRI.
- Fase 8: documentacion final, diagrama criptografico y amenazas conocidas.

No deben considerarse implementados todavia `POST /api/auth/register`, `GET /api/auth/salt`, `POST /api/auth/login`, `/api/vault` ni logout.

## 7. Como continuar

La siguiente fase es la Fase 2. Antes de implementarla hay que conservar estas decisiones:

1. El cliente deriva `authHash` y prepara `wrappedVaultKey`; el servidor nunca deriva contrasenas.
2. El servidor recibe y almacena `authHash`, pero debe volver a hashearlo con Argon2 antes de persistirlo.
3. El registro debe guardar el salt generado por el cliente, las iteraciones, el auth hash procesado, la vault key envuelta y su IV.
4. El login debe comparar el auth hash con Argon2, emitir JWT en cookie httpOnly y devolver solo `wrappedVaultKey` y `wrapIv`.
5. Deben añadirse primero tests de rutas y rate limiting antes de conectar la UI.
6. No guardar secretos en logs, `localStorage`, `sessionStorage` ni respuestas innecesarias.

## 8. Notas para futuras sesiones

- Leer primero [PLAN.md](PLAN.md) y este archivo.
- Comprobar `git status` antes de editar: puede haber cambios locales del usuario.
- No leer ni imprimir el contenido de `server/.env`; solo comprobar que `DATABASE_URL` existe o ejecutar una prueba de conexion.
- Ejecutar comandos del backend desde `server/`. Ejecutar tests/build del frontend desde `client/`.
- Si una sesion de terminal persistente hereda otro directorio, usar `cd` con la ruta absoluta del repositorio.
- La persistencia actual es Supabase PostgreSQL.
- No modificar `client/src/crypto/` al implementar rutas de autenticacion salvo que un test demuestre una incompatibilidad.
