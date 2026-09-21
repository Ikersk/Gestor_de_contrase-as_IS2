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
el nombre de credencial a 30, el usuario a 30, cada URL a 100 y permiten hasta
8 URLs por credencial. Nombre y usuario deben contener al menos una letra. Las credenciales
se validan en el cliente antes de cifrarse; el backend limita ademas el cuerpo
JSON y los blobs cifrados.

El cliente deriva las claves localmente durante el registro y el login. La
contrasena maestra nunca se envia al backend ni se guarda en `localStorage` o
`sessionStorage`; la `vaultKey` solo vive en memoria mientras la sesion esta
abierta.

Con la sesion abierta puedes crear, editar y borrar credenciales desde la
interfaz. Cada item se cifra en el cliente antes de enviarse a `/api/vault`.

El formulario de credenciales se abre en un modal único para crear y editar
accesos. El botón `+ Nueva credencial` inicia un formulario vacío; las acciones
`Editar` y `Resolver` cargan el acceso correspondiente. El generador de
contraseñas usa aleatoriedad criptográfica del navegador y el valor se cifra
antes de guardarse.

La sección **Salud de la Bóveda** analiza únicamente el array de credenciales
ya descifradas en la memoria del cliente. Detecta reutilización y contraseñas
débiles mediante una estimación local de longitud y diversidad, y muestra un
puntaje de 0 a 100. Esta auditoría no realiza peticiones ni envía contraseñas
al servidor. Cada alerta permite abrir el modal de edición para resolverla.

El cambio de contraseña maestra se inicia con el botón correspondiente en la
bóveda y se realiza dentro de una ventana modal. Al cancelar o cerrar, sus
campos se limpian. Tras completarlo, se rota el material derivado, se invalida
la sesión actual y la aplicación solicita iniciar sesión de nuevo.

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

Para revisar manualmente la base de datos, abre el **SQL Editor** de Supabase y
consulta las tablas:

```sql
SELECT * FROM users;
SELECT * FROM vault_items;
```

En `users` deben aparecer el hash del `authHash`, el `kdf_salt`, el
`wrapped_vault_key` y el `wrap_iv`. En `vault_items` deben aparecer únicamente
el `iv` y el `ciphertext`. Estos valores deben ser hashes o cadenas Base64
ilegibles; no deben aparecer contraseñas, usuarios ni URLs en texto plano.

La revisión visual de `ciphertext` es suficiente para esta comprobación manual:
el valor debe ser Base64 y no debe mostrar directamente el contenido de la
credencial. Buscar una palabra legible con `LIKE` no es una prueba válida,
porque el contenido está cifrado antes de convertirse a Base64.

La revisión de la base debe hacerse sobre un entorno de pruebas y las capturas
no deben contener secretos reales.

## Revisión del tráfico en DevTools

Abre las herramientas de desarrollador del navegador, entra en la pestaña
**Network** y usa la aplicación. En las peticiones de registro, login y vault
deben aparecer únicamente material derivado, IVs y blobs Base64; nunca la
contraseña maestra, la Vault Key ni los campos legibles de una credencial.
Evita guardar o compartir capturas que contengan secretos reales.
