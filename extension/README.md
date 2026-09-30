# Arca Shield — Extensión de Navegador Anti-Phishing y Guardián de Autocompletado

Extensión oficial para navegadores Chromium (Google Chrome, Microsoft Edge, Brave, Opera) y Firefox, desarrollada bajo el estándar **Manifest V3**.

Implementa la misma arquitectura de seguridad activa utilizada por gestores enterprise como **1Password** y **Bitwarden** para mitigar ataques de suplantación de identidad (*Phishing* y *Typosquatting*).

---

## 🛡️ Características Principales

1. **Inspección en tiempo real de la barra de direcciones:**
   - Extrae el dominio raíz efectivo (`eTLD+1`) de la pestaña activa en cada evento de navegación.
   - Detecta discrepancias entre el sitio web visitado y las credenciales autorizadas.
2. **Detección Criptográfica de Ataques Homográficos (Punycode / IDN):**
   - Detecta dominios con caracteres de otros alfabetos (cirílico, griego) que imitan visualmente a letras latinas (ejemplo: `pаypal.com` con `а` cirílica).
3. **Detección Algorítmica de Typosquatting:**
   - Compara en tiempo real la distancia de Levenshtein contra marcas y servicios críticos (`g00gle.com`, `paypa1.com`, `faceb00k.com`, etc.).
4. **Bloqueo Activo de Autocompletado:**
   - Si la página es catalogada como riesgosa o suplantadora, el `content_script` altera los formularios de acceso y desactiva el autocompletado (`autocomplete="off"` y `autocomplete="new-password"`), impidiendo que contraseñas guardadas sean capturadas por formularios falsos.
5. **Banner Flotante de Advertencia Roja:**
   - Muestra una alerta visible directamente en la parte superior del sitio web alertando al usuario de la amenaza.
6. **Popup Interactivo:**
   - Informa el estado de seguridad de la pestaña, si utiliza protocolo HTTPS o HTTP, y provee acceso directo a la Bóveda Arca (`http://localhost:5173`).
7. **Interruptor Rápido de Autocompletado:**
   - Botón ON/OFF en la cabecera del popup que apaga o activa todo el autocompletado (iconos en los campos, popover, relleno automático y sugerencias) en todas las pestañas de inmediato.
   - Mientras está en `OFF`, el badge del icono pasa a mostrarse en gris con la etiqueta `OFF` (los avisos de phishing `!` y de HTTP tienen prioridad) y la extensión no entrega credenciales a ningún formulario.
   - El estado se guarda como una única preferencia booleana (`autofill_enabled`) en `chrome.storage.local`; no se almacena ninguna credencial en disco.

---

## 🚀 Cómo Cargar la Extensión en tu Navegador

### En Google Chrome / Brave / Edge:
1. Abre tu navegador y escribe en la barra de direcciones:
   - En Chrome: `chrome://extensions`
   - En Edge: `edge://extensions`
   - En Brave: `brave://extensions`
2. Activa el interruptor **"Modo de desarrollador"** (ubicado en la esquina superior derecha).
3. Haz clic en el botón **"Cargar descomprimida"** (*Load unpacked*).
4. Selecciona la carpeta `extension` ubicada en la raíz del proyecto (relativa a donde clonaste el repositorio), por ejemplo `<ruta-del-repositorio>/extension`.
5. ¡Listo! Verás el icono del escudo **Arca Shield (🛡️)** en tu barra de extensiones.

---

## 🧪 Cómo Probar su Funcionamiento

1. **Prueba de Sitio Seguro:**
   - Entra en `https://github.com`.
   - Abre la extensión Arca Shield haciendo clic en su icono: verás el indicador verde `✓ Verificación Exitosa` y el protocolo `🔒 HTTPS Cifrado`.
2. **Prueba de Sitio Inseguro (HTTP):**
   - Entra a cualquier página que use `http://` en lugar de `https://`.
   - El badge de la extensión cambiará a `HTTP` en color ámbar avisándote de la falta de cifrado en tránsito.
3. **Prueba de Bloqueo de Phishing / Typosquatting:**
   - Si navegas a un dominio sospechoso o con sustitución de caracteres similar a una marca conocida, la extensión mostrará el badge rojo `!` y desplegará el banner de alerta bloqueando el autocompletado en los campos de contraseña.
4. **Prueba del Interruptor de Autocompletado:**
   - Abre el popup en una página con formulario de acceso y pulsa el interruptor **Autocompletado** para ponerlo en `OFF`.
   - Los iconos de los campos desaparecen al instante, el badge del icono pasa a `OFF` en gris y el popup deja de listar credenciales (muestra *«Autocompletado desactivado»*).
   - Vuelve a ponerlo en `ON` y todo se restaura sin recargar la página. El estado persiste tras cerrar y abrir el navegador.

> **Importante:** tras modificar cualquier archivo de esta carpeta, recarga la extensión desde `chrome://extensions` y pulsa **F5** en las pestañas abiertas: los *content scripts* no se reinyectan solos.
