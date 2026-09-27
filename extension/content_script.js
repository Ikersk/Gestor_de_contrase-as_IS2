// Arca Shield Content Script: Autocompletado nativo ultra-rápido estilo Apple / 1Password / Google
// Aislamiento completo con Shadow DOM y diseño adaptativo a Modo Claro / Modo Oscuro

let isPhishingThreat = false;
let currentThreatData = null;
let allVaultCredentials = [];
let matchingCredentials = [];
let lastFilledCredential = null;
let activeDropdownInput = null;

// Recuperar última credencial de la sesión (para flujos multi-paso como Google / Microsoft)
try {
  const cached = sessionStorage.getItem('arca_last_filled');
  if (cached) {
    const parsed = JSON.parse(cached);
    if (parsed && Date.now() - parsed.timestamp < 300000) {
      lastFilledCredential = parsed;
    }
  }
} catch {}

// Consultar al background service worker por la sesión activa de la pestaña
try {
  chrome.runtime.sendMessage({ action: 'GET_LAST_FILLED' }, (response) => {
    if (response?.credential && Date.now() - response.credential.timestamp < 300000) {
      lastFilledCredential = response.credential;
      const { passwordField } = findLoginInputs();
      if (passwordField) {
        checkAndAutoFillPasswordStep(passwordField);
      }
    }
  });
} catch {}

// ── Motor de marcas y dominios integrado para emparejamiento ultra-rápido ──

function extractDomainBrand(rawDomainOrUrl) {
  if (!rawDomainOrUrl) return '';
  let str = rawDomainOrUrl.trim().toLowerCase();
  try {
    if (str.startsWith('http://') || str.startsWith('https://')) {
      str = new URL(str).hostname;
    }
  } catch {}

  str = str.replace(/:\d+$/, '');

  const commonPrefixes = [
    'keycloak', 'auth', 'login', 'accounts', 'account', 'signin', 'sign-in',
    'sso', 'identity', 'id', 'my', 'app', 'portal', 'secure', 'admin', 'www'
  ];

  const parts = str.split('.').filter(Boolean);
  if (parts.length === 0) return '';
  if (parts.length === 1) return parts[0];

  const compoundTlds = ['co', 'com', 'org', 'net', 'edu', 'gob', 'gov', 'mil'];
  const last = parts[parts.length - 1];
  const secondLast = parts[parts.length - 2];

  let domainParts = parts;
  if (parts.length >= 3 && compoundTlds.includes(secondLast) && last.length <= 3) {
    domainParts = parts.slice(0, -2);
  } else {
    domainParts = parts.slice(0, -1);
  }

  while (domainParts.length > 1 && commonPrefixes.includes(domainParts[0])) {
    domainParts.shift();
  }

  return domainParts[domainParts.length - 1] || '';
}

function extractBaseDomain(hostname) {
  const clean = (hostname || '').toLowerCase().trim().replace(/:\d+$/, '');
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const compoundTlds = ['co', 'com', 'org', 'net', 'edu', 'gob', 'gov'];
  const tld = parts[parts.length - 1];
  const second = parts[parts.length - 2];

  if (parts.length >= 3 && compoundTlds.includes(second) && tld.length === 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function computeMatchingCredentials(tabUrl, items) {
  if (!tabUrl || !Array.isArray(items) || items.length === 0) return [];

  let parsedTab;
  try {
    parsedTab = new URL(tabUrl);
  } catch {
    return [];
  }

  const tabHost = parsedTab.hostname.toLowerCase();
  const tabBase = extractBaseDomain(tabHost);
  const tabBrand = extractDomainBrand(tabHost);
  const tabPath = parsedTab.pathname.toLowerCase();

  return items.filter((item) => {
    // 1. Coincidencia por URLs guardadas
    if (item.urls && Array.isArray(item.urls)) {
      const urlMatched = item.urls.some((itemUrl) => {
        if (!itemUrl || typeof itemUrl !== 'string' || itemUrl.trim().length === 0) return false;
        try {
          const parsedItem = new URL(itemUrl.startsWith('http') ? itemUrl : `https://${itemUrl}`);
          const itemHost = parsedItem.hostname.toLowerCase();
          const itemBase = extractBaseDomain(itemHost);
          const itemBrand = extractDomainBrand(itemHost);

          if (itemBase === tabBase || tabHost.endsWith(itemHost) || itemHost.endsWith(tabHost)) {
            return true;
          }
          if (tabBrand && itemBrand && tabBrand.length >= 3 && tabBrand === itemBrand) {
            return true;
          }
          // Soporte Google / Gmail cruzado
          if ((tabBrand === 'google' || tabHost.includes('google.com')) && (itemBrand === 'gmail' || itemHost.includes('gmail.com'))) {
            return true;
          }
          return false;
        } catch {
          return false;
        }
      });
      if (urlMatched) return true;
    }

    // 2. Coincidencia por título (ej. "gmail", "Google", "Cines Unidos")
    if (item.title && typeof item.title === 'string') {
      const cleanTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (cleanTitle.length >= 3) {
        if (tabBrand && (cleanTitle.includes(tabBrand) || tabBrand.includes(cleanTitle))) {
          return true;
        }
        if ((tabBrand === 'google' || tabHost.includes('google.com')) && cleanTitle.includes('gmail')) {
          return true;
        }
        const cleanTabBase = tabBase.split('.')[0].replace(/[^a-z0-9]/g, '');
        if (cleanTitle.includes(cleanTabBase) || cleanTabBase.includes(cleanTitle)) {
          return true;
        }
        if (tabPath.includes(cleanTitle)) {
          return true;
        }
      }
    }

    return false;
  });
}

// ── Carga y sincronización reactiva de credenciales con chrome.storage ──

function loadVaultCredentials() {
  try {
    chrome.storage.local.get('arca_vault_items', (data) => {
      allVaultCredentials = Array.isArray(data?.arca_vault_items) ? data.arca_vault_items : [];
      matchingCredentials = computeMatchingCredentials(window.location.href, allVaultCredentials);
      scanAndAttach();
    });
  } catch {}
}

try {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.arca_vault_items) {
      allVaultCredentials = Array.isArray(changes.arca_vault_items.newValue) ? changes.arca_vault_items.newValue : [];
      matchingCredentials = computeMatchingCredentials(window.location.href, allVaultCredentials);
      scanAndAttach();
    }
  });
} catch {}

// ── Detección de campos del DOM con clasificación y filtrado de elementos fuera de pantalla ──

function isElementVisible(el) {
  if (!el || !document.contains(el) || el.disabled || el.readOnly) return false;
  const type = (el.type || 'text').toLowerCase();
  if (type === 'hidden') return false;

  const style = window.getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
    return false;
  }

  const rect = el.getBoundingClientRect();
  // Validar geometría real en el viewport (evitar inputs invisibles o dummy en Google/Microsoft)
  if (rect.width < 35 || rect.height < 15) return false;
  if (rect.bottom <= 0 || rect.top >= window.innerHeight) return false;
  if (rect.right <= 0 || rect.left >= window.innerWidth) return false;

  return true;
}

function scorePasswordInput(input) {
  let score = 0;
  const name = (input.name || '').toLowerCase();
  const id = (input.id || '').toLowerCase();
  const auto = (input.getAttribute('autocomplete') || '').toLowerCase();
  const type = (input.type || '').toLowerCase();

  if (input.name === 'Passwd') score += 150; // Google visible password input
  if (auto === 'current-password') score += 120;
  if (auto === 'new-password') score += 100;
  if (type === 'password') score += 80;
  if (name.includes('pass') || name.includes('clave')) score += 70;
  if (id.includes('pass') || id.includes('clave')) score += 60;
  if (input.getAttribute('tabindex') !== '-1') score += 30;
  if (input.getAttribute('aria-hidden') !== 'true') score += 20;

  return score;
}

function scoreUserInput(input) {
  let score = 0;
  const name = (input.name || '').toLowerCase();
  const id = (input.id || '').toLowerCase();
  const auto = (input.getAttribute('autocomplete') || '').toLowerCase();
  const type = (input.type || '').toLowerCase();

  if (input.id === 'identifierId') score += 150; // Google email field
  if (input.name === 'identifier') score += 140;
  if (type === 'email') score += 100;
  if (auto === 'username') score += 90;
  if (name === 'username' || name === 'loginfmt' || name === 'usuario') score += 85;
  if (auto === 'email') score += 80;
  if (id.includes('user') || id.includes('email') || id.includes('login')) score += 70;
  if (name.includes('user') || name.includes('email') || name.includes('login')) score += 65;
  if (input.getAttribute('tabindex') !== '-1') score += 20;

  return score;
}

function findLoginInputs() {
  const allInputs = Array.from(document.querySelectorAll('input'));
  const validInputs = allInputs.filter(isElementVisible);

  const passwordCandidates = [];
  const userCandidates = [];

  for (const input of validInputs) {
    const type = (input.type || 'text').toLowerCase();
    const isPass = type === 'password' || input.name === 'Passwd' || input.name?.toLowerCase().includes('pass') || input.id?.toLowerCase().includes('pass');

    if (isPass) {
      passwordCandidates.push({ input, score: scorePasswordInput(input) });
    } else {
      const score = scoreUserInput(input);
      if (score > 0 || type === 'email' || (type === 'text' && (input.form || input.closest('form')))) {
        userCandidates.push({ input, score });
      }
    }
  }

  passwordCandidates.sort((a, b) => b.score - a.score);
  userCandidates.sort((a, b) => b.score - a.score);

  return {
    userField: userCandidates[0]?.input || null,
    passwordField: passwordCandidates[0]?.input || null,
    allUserFields: userCandidates.map((c) => c.input),
    allPasswordFields: passwordCandidates.map((c) => c.input),
  };
}

// ── Inyección nativa que emula frameworks (Google Closure, React, Vue, Angular) ──

function setNativeInputValue(element, value) {
  if (!element || value === undefined || value === null) return;
  element.focus();

  // 1. Evento beforeinput (necesario para Google Closure)
  try {
    element.dispatchEvent(
      new InputEvent('beforeinput', {
        bubbles: true,
        composed: true,
        cancelable: true,
        inputType: 'insertText',
        data: String(value),
      })
    );
  } catch (e) {}

  // 2. Invocar setter nativo del prototipo
  const valueSetter = Object.getOwnPropertyDescriptor(element, 'value')?.set;
  const prototype = Object.getPrototypeOf(element);
  const prototypeValueSetter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;

  if (prototypeValueSetter && valueSetter !== prototypeValueSetter) {
    prototypeValueSetter.call(element, value);
  } else if (valueSetter) {
    valueSetter.call(element, value);
  } else {
    element.value = value;
  }

  // 3. Sincronizar atributos en el DOM
  element.setAttribute('value', value);
  element.setAttribute('data-initial-value', value);

  // 4. Disparar eventos de entrada y teclado
  element.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  try {
    element.dispatchEvent(
      new InputEvent('input', {
        bubbles: true,
        composed: true,
        inputType: 'insertText',
        data: String(value),
      })
    );
  } catch (e) {}

  element.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  element.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Unidentified' }));
  element.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Unidentified' }));

  // 5. Ajustar clases de estado visual en Google Accounts (Floating labels)
  const parentContainer = element.closest('.rFrNMe, .Xb9hP, .form-group, .input-wrapper');
  if (parentContainer) {
    parentContainer.classList.add('CDQnT', 'i9xfre');
    parentContainer.classList.remove('u3bW4e'); // Quitar estado vacío
  }

  // 6. Desenfoque suave para activar validaciones y habilitar el botón "Siguiente" / Submit
  setTimeout(() => {
    element.dispatchEvent(new Event('blur', { bubbles: true, composed: true }));
  }, 35);
}

// ── Aislamiento mediante Shadow DOM (Protección contra CSP y Resets CSS del sitio web) ──

let arcaShadowRoot = null;
let arcaHostElement = null;

function getOrCreateShadowRoot() {
  if (arcaHostElement && document.contains(arcaHostElement) && arcaShadowRoot) {
    return arcaShadowRoot;
  }

  document.getElementById('arca-shield-root')?.remove();

  arcaHostElement = document.createElement('div');
  arcaHostElement.id = 'arca-shield-root';
  Object.assign(arcaHostElement.style, {
    position: 'absolute',
    top: '0',
    left: '0',
    width: '0',
    height: '0',
    zIndex: '2147483647',
    pointerEvents: 'none',
  });

  arcaShadowRoot = arcaHostElement.attachShadow({ mode: 'open' });

  // Inyectar Sistema de Estilos Adaptativo (Modo Claro & Modo Oscuro) dentro del Shadow DOM
  const styleEl = document.createElement('style');
  styleEl.textContent = `
    :host {
      all: initial;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    /* Variables base: Modo Claro (Estilo Apple Safari / Google Chrome) */
    .arca-wrapper {
      --arca-bg: #ffffff;
      --arca-bg-subtle: #f8fafc;
      --arca-bg-hover: #f1f5f9;
      --arca-border: #e2e8f0;
      --arca-text-main: #0f172a;
      --arca-text-muted: #64748b;
      --arca-text-tertiary: #94a3b8;
      --arca-accent: #2563eb;
      --arca-accent-hover: #1d4ed8;
      --arca-accent-bg: rgba(37, 99, 235, 0.08);
      --arca-accent-border: rgba(37, 99, 235, 0.25);
      --arca-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.12), 0 8px 10px -6px rgba(0, 0, 0, 0.05), 0 0 0 1px rgba(0, 0, 0, 0.05);
      --arca-badge-bg: #ffffff;
      --arca-badge-border: #cbd5e1;
      --arca-badge-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
      --arca-badge-stroke: #2563eb;
      --arca-avatar-bg: #2563eb;
      --arca-avatar-text: #ffffff;
      --arca-tag-bg: #f8fafc;
      --arca-tag-text: #475569;
      --arca-input-bg: #ffffff;
      --arca-input-border: #cbd5e1;
      --arca-toast-bg: rgba(15, 23, 42, 0.95);
      --arca-toast-text: #ffffff;
    }

    /* Adaptación automática a Modo Oscuro del Navegador / Sistema Operativo */
    @media (prefers-color-scheme: dark) {
      .arca-wrapper {
        --arca-bg: #0f172a;
        --arca-bg-subtle: #1e293b;
        --arca-bg-hover: #1e293b;
        --arca-border: #334155;
        --arca-text-main: #f8fafc;
        --arca-text-muted: #94a3b8;
        --arca-text-tertiary: #64748b;
        --arca-accent: #38bdf8;
        --arca-accent-hover: #0ea5e9;
        --arca-accent-bg: rgba(56, 189, 248, 0.12);
        --arca-accent-border: rgba(56, 189, 248, 0.3);
        --arca-shadow: 0 14px 36px rgba(0, 0, 0, 0.8), 0 0 16px rgba(56, 189, 248, 0.12), 0 0 0 1px rgba(255, 255, 255, 0.06);
        --arca-badge-bg: rgba(15, 23, 42, 0.95);
        --arca-badge-border: rgba(56, 189, 248, 0.35);
        --arca-badge-shadow: 0 2px 8px rgba(0, 0, 0, 0.5);
        --arca-badge-stroke: #38bdf8;
        --arca-avatar-bg: #0284c7;
        --arca-avatar-text: #ffffff;
        --arca-tag-bg: rgba(15, 23, 42, 0.6);
        --arca-tag-text: #94a3b8;
        --arca-input-bg: #1e293b;
        --arca-input-border: #334155;
        --arca-toast-bg: rgba(15, 23, 42, 0.96);
        --arca-toast-text: #f8fafc;
      }
    }

    /* Insignia en el campo (In-field Badge) */
    .arca-badge-element {
      position: fixed;
      z-index: 2147483646;
      width: 22px;
      height: 22px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      border-radius: 6px;
      background: var(--arca-badge-bg);
      border: 1px solid var(--arca-badge-border);
      box-shadow: var(--arca-badge-shadow);
      transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
      user-select: none;
      pointer-events: auto;
    }
    .arca-badge-element:hover {
      transform: scale(1.08);
      border-color: var(--arca-accent);
      box-shadow: 0 0 8px var(--arca-accent-bg);
    }
    .arca-badge-element svg {
      stroke: var(--arca-badge-stroke);
    }

    /* Popover bajo el formulario / input */
    .arca-popover-card {
      position: fixed;
      z-index: 2147483647;
      background: var(--arca-bg);
      border: 1px solid var(--arca-border);
      border-radius: 12px;
      box-shadow: var(--arca-shadow);
      color: var(--arca-text-main);
      overflow: hidden;
      animation: arca-fade-in 0.12s ease-out;
      pointer-events: auto;
      box-sizing: border-box;
    }
    @keyframes arca-fade-in {
      from { opacity: 0; transform: translateY(-4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .arca-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 9px 12px;
      background: var(--arca-bg-subtle);
      border-bottom: 1px solid var(--arca-border);
      font-size: 11px;
      font-weight: 700;
      color: var(--arca-accent);
      user-select: none;
    }
    .arca-brand {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .arca-brand svg {
      stroke: var(--arca-accent);
    }
    .arca-zk-pill {
      font-size: 9px;
      font-weight: 600;
      color: var(--arca-text-muted);
      letter-spacing: 0.04em;
    }

    .arca-search {
      padding: 6px 10px;
      background: var(--arca-bg);
      border-bottom: 1px solid var(--arca-border);
    }
    .arca-search input {
      width: 100%;
      background: var(--arca-input-bg);
      border: 1px solid var(--arca-input-border);
      border-radius: 6px;
      color: var(--arca-text-main);
      padding: 6px 9px;
      font-size: 11px;
      outline: none;
      box-sizing: border-box;
      font-family: inherit;
    }
    .arca-search input:focus {
      border-color: var(--arca-accent);
    }

    .arca-tag {
      padding: 5px 12px;
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--arca-tag-text);
      background: var(--arca-tag-bg);
      border-bottom: 1px solid var(--arca-border);
    }

    .arca-list {
      max-height: 220px;
      overflow-y: auto;
    }
    .arca-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      cursor: pointer;
      border-bottom: 1px solid var(--arca-border);
      transition: background 0.12s ease;
      user-select: none;
    }
    .arca-item:last-child {
      border-bottom: none;
    }
    .arca-item:hover, .arca-item.active {
      background: var(--arca-bg-hover);
    }
    .arca-avatar {
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: var(--arca-avatar-bg);
      color: var(--arca-avatar-text);
      font-weight: 700;
      font-size: 12px;
      display: grid;
      place-items: center;
      flex-shrink: 0;
    }
    .arca-info {
      flex: 1;
      overflow: hidden;
    }
    .arca-user {
      font-size: 12px;
      font-weight: 600;
      color: var(--arca-text-main);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .arca-title {
      font-size: 10px;
      color: var(--arca-text-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .arca-btn-fill {
      font-size: 10px;
      color: var(--arca-accent);
      background: var(--arca-accent-bg);
      border: 1px solid var(--arca-accent-border);
      padding: 4px 8px;
      border-radius: 5px;
      font-weight: 600;
      transition: all 0.12s ease;
    }
    .arca-item:hover .arca-btn-fill {
      background: var(--arca-accent);
      color: #ffffff;
      border-color: var(--arca-accent);
    }

    .arca-foot {
      padding: 6px 12px;
      background: var(--arca-bg-subtle);
      border-top: 1px solid var(--arca-border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 10px;
    }
    .arca-foot button {
      background: none;
      border: none;
      color: var(--arca-text-muted);
      cursor: pointer;
      font-size: 10px;
      padding: 3px 5px;
      border-radius: 4px;
      font-family: inherit;
    }
    .arca-foot button:hover {
      color: var(--arca-accent);
    }

    .arca-empty {
      padding: 16px 12px;
      text-align: center;
      font-size: 11px;
      color: var(--arca-text-muted);
      line-height: 1.5;
    }
    .arca-btn-vault {
      margin-top: 8px;
      background: var(--arca-accent);
      color: #ffffff;
      border: none;
      padding: 5px 14px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
    }

    /* Notificación Toast */
    .arca-toast {
      position: fixed;
      top: 18px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 2147483647;
      background: var(--arca-toast-bg);
      backdrop-filter: blur(14px);
      border: 1px solid var(--arca-accent-border);
      color: var(--arca-toast-text);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
      animation: arca-toast-in 0.2s ease-out;
      pointer-events: auto;
    }
    @keyframes arca-toast-in {
      from { opacity: 0; transform: translate(-50%, -8px); }
      to { opacity: 1; transform: translate(-50%, 0); }
    }
  `;

  arcaShadowRoot.appendChild(styleEl);

  const wrapper = document.createElement('div');
  wrapper.className = 'arca-wrapper';
  arcaShadowRoot.appendChild(wrapper);

  (document.documentElement || document.body).appendChild(arcaHostElement);
  return arcaShadowRoot;
}

function showAutofillToast(message) {
  const root = getOrCreateShadowRoot();
  const wrapper = root.querySelector('.arca-wrapper');
  wrapper.querySelector('.arca-toast')?.remove();

  const toast = document.createElement('div');
  toast.className = 'arca-toast';
  toast.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <span>${message}</span>
  `;

  wrapper.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.25s ease';
    setTimeout(() => toast.remove(), 260);
  }, 2300);
}

// ── Inyección y Guardado de Credenciales en el DOM y Sesión ──

function fillCredentialsIntoDom(username, password) {
  if (isPhishingThreat) return false;

  const { userField, passwordField } = findLoginInputs();
  let filled = false;

  if (passwordField && password) {
    setNativeInputValue(passwordField, password);
    filled = true;
  }

  if (userField && username) {
    setNativeInputValue(userField, username);
    filled = true;
  }

  // Guardar en sesión de pestaña local y en background service worker
  if (username || password) {
    lastFilledCredential = {
      username: username || '',
      password: password || '',
      timestamp: Date.now(),
    };
    try {
      sessionStorage.setItem('arca_last_filled', JSON.stringify(lastFilledCredential));
    } catch {}
    try {
      chrome.runtime.sendMessage({
        action: 'SET_LAST_FILLED',
        credential: lastFilledCredential,
      });
    } catch {}
  }

  showAutofillToast(`Autocompletado con Arca: ${username || 'Cuenta'}`);

  // Enfoque inteligente al botón de avance / envío
  if (userField && !passwordField) {
    const nextBtn = document.querySelector(
      '#identifierNext button, #identifierNext, button[type="submit"], input[type="submit"], button[jsname="LgbsSe"]'
    );
    if (nextBtn) nextBtn.focus();
  } else if (passwordField) {
    const submitBtn = document.querySelector(
      '#passwordNext button, #passwordNext, button[type="submit"], input[type="submit"], #kc-login'
    );
    if (submitBtn) submitBtn.focus();
  }

  removeInlineDropdown();
  return filled;
}

// ── Autocompletado Inmediato de Contraseña en Formularios de 2 Pasos (Google / Microsoft) ──

function checkAndAutoFillPasswordStep(passwordField) {
  if (!passwordField || passwordField.dataset.arcaAutoFilled === 'true') return;

  // 1. Si tenemos la credencial guardada en la sesión del Paso 1
  if (lastFilledCredential && lastFilledCredential.password) {
    passwordField.dataset.arcaAutoFilled = 'true';
    setNativeInputValue(passwordField, lastFilledCredential.password);
    showAutofillToast(`Contraseña completada para ${lastFilledCredential.username || 'tu cuenta'}`);
    const submitBtn = document.querySelector('#passwordNext button, button[type="submit"], input[type="submit"]');
    if (submitBtn) submitBtn.focus();
    return;
  }

  // 2. Si no la tenemos en sesión pero la pantalla muestra el correo (ej. "herrera30723358@usm.edu.ve")
  const pageText = document.body?.innerText || '';
  const emailAttr = document.querySelector('[data-email]')?.getAttribute('data-email') || '';

  const matchedByScreen = matchingCredentials.find((c) => c.username && (pageText.includes(c.username) || emailAttr.includes(c.username))) ||
                          allVaultCredentials.find((c) => c.username && (pageText.includes(c.username) || emailAttr.includes(c.username)));

  if (matchedByScreen && matchedByScreen.password) {
    passwordField.dataset.arcaAutoFilled = 'true';
    setNativeInputValue(passwordField, matchedByScreen.password);
    lastFilledCredential = { username: matchedByScreen.username, password: matchedByScreen.password, timestamp: Date.now() };
    showAutofillToast(`Contraseña completada para ${matchedByScreen.username}`);
    const submitBtn = document.querySelector('#passwordNext button, button[type="submit"], input[type="submit"]');
    if (submitBtn) submitBtn.focus();
    return;
  }

  // 3. Si solo hay 1 credencial coincidente para este dominio en la bóveda, autocompletarla de inmediato
  if (matchingCredentials.length === 1 && matchingCredentials[0].password) {
    const single = matchingCredentials[0];
    passwordField.dataset.arcaAutoFilled = 'true';
    setNativeInputValue(passwordField, single.password);
    lastFilledCredential = { username: single.username, password: single.password, timestamp: Date.now() };
    showAutofillToast(`Contraseña completada para ${single.username}`);
    const submitBtn = document.querySelector('#passwordNext button, button[type="submit"], input[type="submit"]');
    if (submitBtn) submitBtn.focus();
  }
}

// ── Interfaz Minimalista (Badge integrado + Popover nativo anclado bajo el input) ──

function removeInlineDropdown() {
  const root = getOrCreateShadowRoot();
  root.querySelector('.arca-popover-card')?.remove();
  activeDropdownInput = null;
}

function positionPopover(input, popover) {
  if (!input || !document.contains(input) || !popover) return;

  const rect = input.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0 || !isElementVisible(input)) {
    removeInlineDropdown();
    return;
  }

  const popoverWidth = Math.max(300, Math.min(rect.width, 420));
  const popoverHeight = popover.offsetHeight || 250;

  // Anclado directamente debajo del input
  let top = rect.bottom + 6;
  if (top + popoverHeight > window.innerHeight - 8 && rect.top > popoverHeight + 10) {
    top = rect.top - popoverHeight - 6; // Mostrar arriba si no cabe abajo
  }

  let left = Math.max(8, Math.min(rect.left, window.innerWidth - popoverWidth - 8));

  popover.style.top = `${top}px`;
  popover.style.left = `${left}px`;
  popover.style.width = `${popoverWidth}px`;
}

function attachFieldIcon(input) {
  if (input._arcaIconAttached && document.contains(input._arcaIconAttached)) {
    return;
  }

  const root = getOrCreateShadowRoot();
  const wrapper = root.querySelector('.arca-wrapper');

  const icon = document.createElement('div');
  icon.className = 'arca-badge-element';
  icon.title = 'Arca Shield — Autocompletar';
  icon.innerHTML = `
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  `;

  function updateIconPosition() {
    if (!document.contains(input)) {
      icon.remove();
      return;
    }

    const rect = input.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0 || !isElementVisible(input)) {
      icon.style.display = 'none';
      return;
    }

    icon.style.display = 'flex';
    icon.style.top = `${rect.top + (rect.height - 22) / 2}px`;
    icon.style.left = `${rect.right - 26}px`;

    // Si el menú está abierto para este input, reubicarlo suavemente
    const activePopover = wrapper.querySelector('.arca-popover-card');
    if (activePopover && activeDropdownInput === input) {
      positionPopover(input, activePopover);
    }
  }

  updateIconPosition();
  input._arcaIconAttached = icon;

  window.addEventListener('resize', updateIconPosition, { passive: true });
  window.addEventListener('scroll', updateIconPosition, { passive: true, capture: true });

  icon.addEventListener('mousedown', (e) => {
    e.preventDefault();
    e.stopPropagation();
    toggleInlineDropdown(input);
  });

  wrapper.appendChild(icon);

  // Al hacer clic o foco en el campo, mostrar el menú bajo el input
  input.addEventListener('focus', () => showInlineDropdown(input));
  input.addEventListener('click', () => showInlineDropdown(input));

  // Enter para autocompletar de inmediato si hay una sola cuenta
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && matchingCredentials.length === 1 && wrapper.querySelector('.arca-popover-card')) {
      e.preventDefault();
      const chosen = matchingCredentials[0];
      fillCredentialsIntoDom(chosen.username, chosen.password);
    }
  });
}

function toggleInlineDropdown(input) {
  const root = getOrCreateShadowRoot();
  if (root.querySelector('.arca-popover-card') && activeDropdownInput === input) {
    removeInlineDropdown();
  } else {
    showInlineDropdown(input);
  }
}

function showInlineDropdown(input) {
  removeInlineDropdown();
  if (isPhishingThreat) return;

  const rect = input.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0 || !isElementVisible(input)) return;

  activeDropdownInput = input;

  const root = getOrCreateShadowRoot();
  const wrapper = root.querySelector('.arca-wrapper');

  const popover = document.createElement('div');
  popover.className = 'arca-popover-card';

  const isPassField = input.type === 'password' || input.name === 'Passwd' || input.name?.toLowerCase().includes('pass');
  const hasMatches = matchingCredentials && matchingCredentials.length > 0;
  const hasAnyVault = allVaultCredentials && allVaultCredentials.length > 0;
  const otherCredentials = allVaultCredentials.filter((c) => !matchingCredentials.some((m) => m.id === c.id));

  popover.innerHTML = `
    <div class="arca-head">
      <div class="arca-brand">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>Arca Shield</span>
      </div>
      <span class="arca-zk-pill">Zero-Knowledge</span>
    </div>

    ${
      hasAnyVault && (allVaultCredentials.length > 2 || !hasMatches)
        ? `
      <div class="arca-search">
        <input type="text" id="arca-search-field" placeholder="Buscar cuenta o servicio..." autocomplete="off" />
      </div>
    `
        : ''
    }

    <div class="arca-list" id="arca-popover-list">
      ${renderMinimalistItems(matchingCredentials, otherCredentials, hasAnyVault)}
    </div>

    <div class="arca-foot">
      ${
        isPassField
          ? `
        <button id="arca-gen-pass" type="button" style="color: #10b981; font-weight: 600;">
          + Generar clave segura
        </button>
      `
          : `<span style="color: var(--arca-text-muted);">1 clic para autocompletar</span>`
      }
      <button id="arca-open-vault" type="button">Abrir Bóveda</button>
    </div>
  `;

  wrapper.appendChild(popover);
  positionPopover(input, popover);

  // Búsqueda en vivo reactiva
  const searchInput = popover.querySelector('#arca-search-field');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      const filtered = allVaultCredentials.filter((c) => {
        return (
          (c.username && c.username.toLowerCase().includes(q)) ||
          (c.title && c.title.toLowerCase().includes(q))
        );
      });
      const container = popover.querySelector('#arca-popover-list');
      if (container) {
        container.innerHTML = renderFilteredItems(filtered);
        bindClickEvents(container, filtered);
      }
    });
  }

  // Generador de claves
  popover.querySelector('#arca-gen-pass')?.addEventListener('click', () => {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
    const array = new Uint32Array(20);
    crypto.getRandomValues(array);
    const pass = Array.from(array, (x) => chars[x % chars.length]).join('');

    setNativeInputValue(input, pass);
    navigator.clipboard?.writeText(pass);
    showAutofillToast('Clave segura generada y copiada al portapapeles');
    removeInlineDropdown();
  });

  // Abrir bóveda web
  popover.querySelector('#arca-open-vault')?.addEventListener('click', () => {
    window.open('http://localhost:5173', '_blank');
    removeInlineDropdown();
  });

  popover.querySelector('#arca-btn-open-unlock')?.addEventListener('click', () => {
    window.open('http://localhost:5173', '_blank');
    removeInlineDropdown();
  });

  const listContainer = popover.querySelector('#arca-popover-list');
  if (listContainer) {
    bindCombinedClickEvents(listContainer, matchingCredentials, otherCredentials);
  }
}

function renderMinimalistItems(matches, others, hasAny) {
  if (!hasAny) {
    return `
      <div class="arca-empty">
        La Bóveda Arca está bloqueada o vacía.<br />
        <button class="arca-btn-vault" id="arca-btn-open-unlock" type="button">Abrir e Iniciar Sesión</button>
      </div>
    `;
  }

  let html = '';

  if (matches.length > 0) {
    html += `<div class="arca-tag">Sugerida para este sitio (${matches.length})</div>`;
    html += matches
      .map((m, idx) => renderItemRow(m, `match-${idx}`, idx === 0))
      .join('');
  }

  if (others.length > 0) {
    html += `<div class="arca-tag">${matches.length > 0 ? 'Otras cuentas' : 'Cuentas en tu Bóveda'} (${others.length})</div>`;
    html += others
      .map((m, idx) => renderItemRow(m, `other-${idx}`, false))
      .join('');
  }

  return html;
}

function renderFilteredItems(items) {
  if (!items || items.length === 0) {
    return `<div class="arca-empty">No se encontraron cuentas coincidentes.</div>`;
  }
  return items.map((m, idx) => renderItemRow(m, `filter-${idx}`, idx === 0)).join('');
}

function renderItemRow(m, dataKey, isHighlight) {
  const initial = (m.title || m.username || 'A').charAt(0).toUpperCase();
  return `
    <div class="arca-item ${isHighlight ? 'active' : ''}" data-key="${dataKey}">
      <div class="arca-avatar">${initial}</div>
      <div class="arca-info">
        <div class="arca-user">${m.username || 'Usuario'}</div>
        <div class="arca-title">${m.title || 'Acceso'}</div>
      </div>
      <span class="arca-btn-fill">Autocompletar</span>
    </div>
  `;
}

function bindCombinedClickEvents(container, matches, others) {
  container.querySelectorAll('.arca-item').forEach((row) => {
    row.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const key = row.dataset.key;
      let chosen = null;
      if (key?.startsWith('match-')) {
        const idx = Number(key.replace('match-', ''));
        chosen = matches[idx];
      } else if (key?.startsWith('other-')) {
        const idx = Number(key.replace('other-', ''));
        chosen = others[idx];
      }
      if (chosen) {
        fillCredentialsIntoDom(chosen.username, chosen.password);
      }
    });
  });
}

function bindClickEvents(container, items) {
  container.querySelectorAll('.arca-item').forEach((row) => {
    row.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const key = row.dataset.key;
      const idx = Number(key?.replace('filter-', ''));
      const chosen = items[idx];
      if (chosen) {
        fillCredentialsIntoDom(chosen.username, chosen.password);
      }
    });
  });
}

// Cerrar dropdown al hacer clic fuera o Escape
document.addEventListener('click', (e) => {
  const root = getOrCreateShadowRoot();
  const wrapper = root.querySelector('.arca-wrapper');
  const path = e.composedPath ? e.composedPath() : [];
  const clickedInsideExtension = path.some((el) => el === wrapper || el?.classList?.contains?.('arca-popover-card') || el?.classList?.contains?.('arca-badge-element'));

  if (!clickedInsideExtension) {
    removeInlineDropdown();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') removeInlineDropdown();
});

// ── Escaneo y vinculación automática continua ──

function scanAndAttach() {
  if (isPhishingThreat) return;

  const { allUserFields, allPasswordFields, passwordField } = findLoginInputs();

  allUserFields.forEach((u) => attachFieldIcon(u));
  allPasswordFields.forEach((p) => attachFieldIcon(p));

  // Autocompletado inmediato de contraseña en flujos de 2 pasos
  if (passwordField) {
    checkAndAutoFillPasswordStep(passwordField);
  }
}

// Escuchar foco globalmente (captura cuando Google o Keycloak enfocan un campo automáticamente)
document.addEventListener('focusin', (e) => {
  const target = e.target;
  if (target && target.tagName === 'INPUT' && isElementVisible(target)) {
    attachFieldIcon(target);
    const type = (target.type || '').toLowerCase();
    if (type === 'password' || target.name === 'Passwd' || target.name?.toLowerCase().includes('pass')) {
      checkAndAutoFillPasswordStep(target);
    }
  }
});

// Observador de mutaciones DOM robusto con soporte para cambios de atributos en SPAs
let mutationTimer = null;
const observer = new MutationObserver(() => {
  if (mutationTimer) clearTimeout(mutationTimer);
  mutationTimer = setTimeout(scanAndAttach, 60);
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ['class', 'style', 'hidden', 'tabindex', 'aria-hidden'],
});

// Escuchar peticiones desde el popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'PHISHING_ALERT') {
    isPhishingThreat = true;
    currentThreatData = message.data;
  } else if (message.action === 'AUTOFILL_CREDENTIALS') {
    const success = fillCredentialsIntoDom(message.username, message.password);
    sendResponse({ success });
    return true;
  }
});

// Sincronización en tiempo real desde la aplicación Arca (localhost o 127.0.0.1)
window.addEventListener('message', (event) => {
  if (event.data?.type === 'ARCA_VAULT_SYNC' && Array.isArray(event.data.credentials)) {
    chrome.runtime.sendMessage({
      action: 'SAVE_VAULT_ITEMS',
      items: event.data.credentials,
    });
  } else if (event.data?.type === 'ARCA_VAULT_CLEAR') {
    chrome.runtime.sendMessage({
      action: 'CLEAR_VAULT_ITEMS',
    });
  }
});

if ((window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') && window.location.port === '5173') {
  window.postMessage({ type: 'ARCA_REQUEST_SYNC' }, '*');
}

// Ciclo de inicialización garantizado (inmediato, 100ms, 300ms, 800ms, 1800ms)
loadVaultCredentials();
setTimeout(scanAndAttach, 80);
setTimeout(scanAndAttach, 250);
setTimeout(scanAndAttach, 600);
setTimeout(scanAndAttach, 1500);
