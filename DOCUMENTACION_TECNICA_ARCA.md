# ARCA — Documentación Técnica Completa

> Gestor de Contraseñas de Conocimiento Cero (Zero-Knowledge Password Manager)  
> Versión 0.1.0 · Arquitectura cliente-servidor · Cifrado local garantizado

---

## Tabla de Contenidos

1. [¿Qué es ARCA?](#1-qué-es-arca)
2. [¿Qué puede hacer ARCA?](#2-qué-puede-hacer-arca)
3. [Arquitectura General](#3-arquitectura-general)
4. [Modelo de Seguridad: Cero Conocimiento](#4-modelo-de-seguridad-cero-conocimiento)
5. [Stack Tecnológico y Por Qué](#5-stack-tecnológico-y-por-qué)
6. [Sistema Criptográfico en Detalle](#6-sistema-criptográfico-en-detalle)
7. [Módulos del Sistema](#7-módulos-del-sistema)
8. [Servidor y Base de Datos](#8-servidor-y-base-de-datos)
9. [Extensión de Navegador](#9-extensión-de-navegador)
10. [Librerías Externas: Origen y Justificación](#10-librerías-externas-origen-y-justificación)
11. [Algoritmos Propios vs Externos](#11-algoritmos-propios-vs-externos)
12. [Flujos Criptográficos Completos](#12-flujos-criptográficos-completos)

---

## 1. ¿Qué es ARCA?

ARCA es un **gestor de contraseñas de conocimiento cero** (Zero-Knowledge Password Manager). Esto significa que:

- **El servidor nunca conoce tu contraseña maestra.** Ni en texto plano, ni en ninguna forma reversible.
- **El servidor nunca conoce el contenido de tu bóveda.** Solo almacena datos cifrados (blobs) que son inútiles sin la clave.
- **Todo el cifrado y descifrado ocurre exclusivamente en tu navegador.**
- **Si el servidor es hackeado, el atacante solo obtiene datos cifrados que no puede descifrar.**

ARCA implementa el mismo modelo de seguridad usado por gestores de contraseñas de nivel industrial como **Bitwarden** y **1Password**, con la diferencia de que su código es completamente auditable, transparente y libre de dependencias de terceros para operaciones criptográficas.

---

## 2. ¿Qué puede hacer ARCA?

### 🔐 Gestión de Credenciales y Visibilidad
- Crear, editar, visualizar, eliminar y organizar credenciales (sitio, usuario, contraseña, URLs).
- **Control total de visibilidad de contraseña:** botón de revelar/ocultar integrado en todos los formularios (edición, creación, cambio de clave maestra y vista de detalle) para permitir auditar y modificar la contraseña con total certeza.
- Marcar credenciales como favoritas.
- Buscar y filtrar credenciales en tiempo real.
- Soporte para múltiples URLs por credencial (hasta 8).

### 🔑 Generador de Contraseñas Seguras
- Genera contraseñas de 8 a 32 caracteres.
- Configurable: mayúsculas, minúsculas, números, símbolos.
- Usa `crypto.getRandomValues()` — aleatoriedad criptográfica real con rechazo de sesgo de módulo, no `Math.random()`.

### 🛡️ Protocolo de Contraseña Maestra
- Valida en tiempo real que la contraseña cumple 5 criterios de entropía durante el registro y cambio de contraseña.
- En login no evalúa ni restringe la entrada: preserva el principio de cero conocimiento (la contraseña maestra nunca se somete a pre-validaciones innecesarias en el cliente al iniciar sesión).
- Muestra nivel de seguridad: Muy Débil → Débil → Media → Fuerte → Excelente.
- Calcula bits de entropía reales basados en el espacio de caracteres usado.

### 🤖 CAPTCHA Anti-Bot (SHA-256 Proof of Work)
- Requiere que el navegador resuelva un desafío criptográfico SHA-256 real (Hashcash) en segundo plano mediante un Web Worker.
- Hace que los ataques automatizados y de fuerza bruta masiva sean computacionalmente prohibitivos.
- Diseñado desde cero, sin trackers de terceros ni librerías externas.

### 🎣 Anti-Phishing Shield
- Analiza todas las URLs guardadas en busca de ataques de suplantación antes de almacenarlas.
- Detecta 7 tipos de amenazas: homoglifos Unicode, typosquatting (distancia Levenshtein), Punycode, TLD falsos, marcas en subdominios/paths y protocolos inseguros.
- Protege 25+ marcas globales de alto impacto y bloquea activamente URLs fraudulentas.

### 🔍 Have I Been Pwned (HIBP)
- Verifica si tus contraseñas aparecen en filtraciones públicas conocidas.
- Usa k-Anonimato: **solo los primeros 5 caracteres del hash SHA-1** salen del navegador.
- La contraseña en texto plano **nunca** abandona el dispositivo.

### 📊 Auditoría de Salud de la Bóveda
- Detecta contraseñas reutilizadas entre diferentes servicios.
- Detecta contraseñas débiles (longitud < 10 o entropía < 50 bits).
- Combina resultados con HIBP para calcular un puntaje global de seguridad de la bóveda.

### 🔢 TOTP — Segundo Factor de Autenticación
- Almacena secretos TOTP cifrados junto a las credenciales dentro del blob AES-256-GCM.
- Genera códigos 2FA de 6 dígitos cada 30 segundos (RFC 6238).
- Compatible con Google Authenticator, Authy, y cualquier app TOTP estándar.
- Soporta URIs `otpauth://` para importación directa.

### 🧩 Extensión de Navegador
- Autorrellena credenciales en formularios de login detectados automáticamente.
- Se sincroniza con la bóveda activa en tiempo real vía `postMessage`.
- Limpieza inmediata de memoria al cerrar sesión.

---

## 3. Arquitectura General

```
┌─────────────────────────────────────────────────────────────┐
│                    NAVEGADOR (Cliente)                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Interfaz React                    │   │
│  │  - Dashboard de Bóveda                              │   │
│  │  - Formulario de Edición con Revelado de Contraseña │   │
│  │  - Medidor de Entropía y Protocolo                  │   │
│  │  - PoW CAPTCHA Minimalista (SHA-256)                │   │
│  │  - Auditoría de Salud y Escudo Anti-Phishing        │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │                               │
│  ┌──────────────────────────▼──────────────────────────┐   │
│  │             Capa Criptográfica (Nativa)             │   │
│  │  - Web Crypto API (SubtleCrypto)                    │   │
│  │  - PBKDF2-SHA-256 (600,000 iteraciones)             │   │
│  │  - HKDF-SHA-256 (Separación de Subclaves)           │   │
│  │  - AES-256-GCM (Cifrado Autenticado AEAD)           │   │
│  │  - Vault Key (32 bytes aleatorios, SOLO en RAM)     │   │
│  └──────────────────────────┬──────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────┘
                              │ HTTPS / Cookies HttpOnly
┌─────────────────────────────▼───────────────────────────────┐
│                    SERVIDOR (Node / Express)                 │
│                                                             │
│  - Endpoint de Registro (recibe authHash, almacena wrapped) │
│  - Endpoint de Salt (devuelve kdfSalt por email)            │
│  - Endpoint de Login (valida authHash, emite sesión JWT)    │
│  - CRUD de Bóveda (almacena blobs cifrados opacos)          │
│  - Base de Datos (SQLite / PostgreSQL)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Modelo de Seguridad: Cero Conocimiento

El principio rector de ARCA es que **el servidor es un almacenamiento no confiable**.

```
Contraseña Maestra (Entrada del usuario)
  │
  ├─► PBKDF2 (600,000 iteraciones + Salt 16 bytes)
  │     └─► Master Key (256 bits)
  │           │
  │           ├─► HKDF [info="encryption"] ──► Encryption Key (AES-256-GCM)
  │           │                                      │
  │           │                                      └─► Cifra / Descifra la Vault Key
  │           │
  │           └─► HKDF [info="authentication"] ──► Auth Hash (256 bits)
  │                                                  │
  │                                                  └─► Se envía al Servidor (Login/Registro)
```

1. **Nunca viaja la contraseña maestra:** Solo el `authHash` llega al servidor.
2. **El `authHash` no puede derivar la `Encryption Key`:** HKDF garantiza la separación unidireccional de subclaves mediante dominios criptográficos independientes (`info` strings distintos).
3. **La `Vault Key` protege los datos:** Cada usuario tiene una clave de 256 bits generada con `crypto.getRandomValues(32)`. Esta clave cifra cada ítem de la bóveda individualmente con un IV de 12 bytes aleatorio.

---

## 5. Stack Tecnológico y Por Qué

| Tecnología | Componente | Justificación |
|---|---|---|
| **TypeScript / React** | Frontend | Tipado estático estricto, reactividad fluida, control total de estado en memoria. |
| **Web Crypto API (`window.crypto.subtle`)** | Criptografía cliente | Implementación nativa en C++ del motor del navegador. Resistente a ataques de temporización (constant-time) y con aceleración por hardware (AES-NI). |
| **Vite** | Bundler Frontend | Compilación ultrarrápida, soporte nativo de ESM y Workers. |
| **Node.js + Express** | Servidor API | Ligero, robusto, ecosistema maduro de middleware de seguridad. |
| **SQLite / PostgreSQL** | Base de Datos | Persistencia relacional ACID de metadatos y blobs cifrados. |

---

## 6. Sistema Criptográfico en Detalle

### 6.1 PBKDF2-SHA-256
- **Iteraciones:** 600,000 (alineado con recomendaciones OWASP 2023+).
- **Salt:** 16 bytes criptográficamente seguros por usuario.
- **Función hash:** SHA-256.

### 6.2 HKDF (RFC 5869)
- **Subclave 1 (`info = "encryption"`):** Clave AES-256-GCM para envolver/desenvolver la Vault Key.
- **Subclave 2 (`info = "authentication"`):** Hash SHA-256 codificado en base64 para autenticación en el servidor.

### 6.3 AES-256-GCM (NIST SP 800-38D)
- **Modo:** Galois/Counter Mode (GCM), cifrado autenticado con datos asociados (AEAD).
- **Tamaño de clave:** 256 bits (32 bytes).
- **IV / Nonce:** 12 bytes aleatorios únicos por cada operación de cifrado.
- **Tag de autenticación:** 128 bits (16 bytes), previene alteraciones y manipulación de datos.

---

## 7. Módulos del Sistema

### 7.1 Módulo de Autenticación (`client/src/auth.ts`)
Controla el flujo de registro, login, cambio de contraseña maestra y cierre de sesión. Mantiene la `Vault Key` únicamente en variables de módulo en memoria RAM, limpiándola por completo en `logout` o al cerrar la ventana.

### 7.2 Módulo de Bóveda (`client/src/vault.ts`)
Implementa las operaciones CRUD de credenciales: serializa a JSON, cifra con AES-256-GCM usando la Vault Key activa y transmite el payload cifrado al servidor. Al consultar credenciales, descifra cada blob en el cliente.

### 7.3 Interfaz de Usuario y Formulario de Edición (`client/src/main.tsx`)
- Formulario de guardado y actualización de accesos con campo de contraseña que incluye **botón para mostrar/ocultar la clave en texto plano** mediante un botón de ojo accesible.
- Selector de tema visual (Dark / Light) con estética minimalista y moderna.
- Notificaciones Toast en tiempo real.

### 7.4 Escudo Anti-Phishing (`client/src/anti-phishing.ts`)
Inspecciona URLs antes de guardarlas y alerta si detecta suplantación de dominios de bancos, servicios en la nube o redes sociales.

### 7.5 Verificación Have I Been Pwned (`client/src/hibp.ts`)
Consulta la API Pwned Passwords mediante k-Anonimato (solo prefijo SHA-1 de 5 caracteres) para alertar sobre contraseñas comprometidas.

### 7.6 Auditoría de Salud (`client/src/vault-health.ts`)
Calcula métricas de calidad de la bóveda: contraseñas débiles, repetidas o filtradas.

### 7.7 Generador Seguro (`client/src/password-generator.ts`)
Genera contraseñas aleatorias usando `crypto.getRandomValues()` sin sesgo de módulo.

### 7.8 CAPTCHA Proof of Work (`client/src/CaptchaBox.tsx`)
Desafío Hashcash SHA-256 que se ejecuta de forma asíncrona en un Web Worker para proteger los endpoints contra ataques automatizados.

---

## 8. Servidor y Base de Datos

El servidor expone una API REST protegida por:
- Cookies HttpOnly con firma JWT (`SameSite=Strict`).
- Rate limiting por IP.
- Cabeceras de seguridad estrictas mediante Helmet (Content Security Policy).
- Almacenamiento exclusivo de blobs opacos y hashes derivados (con hash adicional `bcrypt` en base de datos).

---

## 9. Extensión de Navegador

Ubicada en `extension/`, se comunica con la pestaña activa mediante `window.postMessage` para recibir temporalmente los accesos necesarios para autorrellenar formularios de inicio de sesión. No almacena información en disco.

---

## 10. Librerías Externas: Origen y Justificación

| Librería | Propósito | Justificación |
|---|---|---|
| **otpauth** | TOTP / RFC 6238 | Estándar auditado para sincronización de tiempo y HMAC-SHA1. |
| **express** | Framework HTTP | Servidor minimalista y robusto. |
| **helmet** | Seguridad HTTP | Inyección de cabeceras CSP, HSTS, X-Frame-Options. |
| **jsonwebtoken** | Sesiones | Manejo estándar de tokens JWT en cookies HttpOnly. |
| **bcryptjs** | Hash secundario DB | Protección adicional del authHash en reposo. |
| **zod** | Validación | Esquemas de validación estricta para solicitudes HTTP. |

---

## 11. Algoritmos Propios vs Externos

| Sistema / Componente | Tipo | Implementación |
|---|---|---|
| **KDF & Derivación de Subclaves** | Propio sobre WebCrypto | `crypto/kdf.js` |
| **Envoltura de Vault Key** | Propio sobre WebCrypto | `crypto/vault-key.js` |
| **Cifrado de Ítems Bóveda** | Propio sobre WebCrypto | `crypto/cipher.js` |
| **Anti-Phishing Shield** | Algoritmo propio | `anti-phishing.ts` |
| **PoW CAPTCHA (Hashcash)** | Algoritmo propio | `CaptchaBox.tsx` |
| **Auditoría de Salud** | Algoritmo propio | `vault-health.ts` |
| **k-Anonimato HIBP** | Implementación propia | `hibp.ts` |
| **PBKDF2 / HKDF / AES-GCM** | Estándar NIST | Motor nativo del navegador (`SubtleCrypto`) |
| **TOTP RFC 6238** | Estándar IETF | `otpauth` |

---

## 12. Flujos Criptográficos Completos

### Registro
```
Usuario: email + contraseña maestra
  │ (En navegador)
  ├─► salt = crypto.getRandomValues(16)
  ├─► masterKey = PBKDF2(pass, salt, 600000)
  ├─► {encKey, authHash} = HKDF(masterKey)
  ├─► vaultKey = crypto.getRandomValues(32)
  └─► wrappedVaultKey = AES-GCM-Encrypt(encKey, vaultKey)
        │
        └─► POST /api/auth/register { email, kdfSalt, kdfIterations, authHash, wrappedVaultKey, wrapIv }
```

### Inicio de Sesión
```
Usuario: email + contraseña maestra
  │
  ├─► GET /api/auth/salt?email ──► { kdfSalt, kdfIterations }
  ├─► masterKey = PBKDF2(pass, kdfSalt, kdfIterations)
  ├─► {encKey, authHash} = HKDF(masterKey)
  └─► POST /api/auth/login { email, authHash }
        │
        └─► Recibe { wrappedVaultKey, wrapIv }
              └─► vaultKey = AES-GCM-Decrypt(encKey, wrapIv, wrappedVaultKey)
                    └─► Almacenada SOLO en memoria RAM
```

---

## Resumen de Garantías de Seguridad

| Garantía | Mecanismo técnico |
|---|---|
| **Contraseña maestra nunca transmitida** | Derivación PBKDF2 + HKDF local; solo viaja `authHash`. |
| **Bóveda completamente ilegible para el servidor** | Cifrado AES-256-GCM en el cliente antes del envío. |
| **Inviolabilidad ante brechas del servidor** | El servidor no posee claves maestras ni claves de bóveda. |
| **Resistencia a ataques de fuerza bruta** | PBKDF2 con 600,000 iteraciones (~300ms por cómputo). |
| **Protección contra bots y automatizaciones** | Desafío SHA-256 Proof of Work en Web Worker. |
| **Autenticidad e integridad de datos** | Tag de autenticación GCM de 128 bits (AEAD). |
| **Privacidad en consultas de brechas** | Modelo de k-Anonimato con prefijos SHA-1 de 5 caracteres. |

---

*ARCA — Zero-Knowledge Password Manager · Documentación Técnica v0.1.0*
