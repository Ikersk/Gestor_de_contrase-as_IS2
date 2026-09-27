// Arca Shield Background Service Worker (Manifest V3)

const POPULAR_TARGETS = [
  'paypal.com',
  'google.com',
  'accounts.google.com',
  'microsoft.com',
  'login.microsoftonline.com',
  'apple.com',
  'amazon.com',
  'facebook.com',
  'instagram.com',
  'github.com',
  'netflix.com',
  'twitter.com',
  'x.com',
  'linkedin.com',
  'dropbox.com',
  'spotify.com',
  'binance.com',
  'coinbase.com',
  'bankofamerica.com',
  'chase.com',
  'wellsfargo.com',
  'santander.com',
  'bbva.com',
  'mercadolibre.com',
];

const CONFUSABLES = {
  '\u0430': 'a (Cirílico)',
  '\u0441': 'c (Cirílico)',
  '\u0435': 'e (Cirílico)',
  '\u043E': 'o (Cirílico)',
  '\u0440': 'p (Cirílico)',
  '\u0455': 's (Cirílico)',
  '\u0456': 'i (Cirílico)',
  '\u0458': 'j (Cirílico)',
  '\u0443': 'y (Cirílico)',
  '\u0445': 'x (Cirílico)',
  '\u03BF': 'o (Griego)',
  '\u03BD': 'v (Griego)',
  '\u03C1': 'p (Griego)',
};

function calculateLevenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
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

function normalizeSubstitutions(domain) {
  return domain
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

function isValidFqdn(hostname) {
  const clean = (hostname || '').toLowerCase().trim().replace(/:\d+$/, '');
  if (!clean) return false;
  if (clean === 'localhost') return true;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) return true;
  if (!clean.includes('.')) return false;
  const parts = clean.split('.');
  if (parts.some((p) => p.length === 0)) return false;
  const tld = parts[parts.length - 1];
  return /^[a-z]{2,24}$/i.test(tld);
}

function evaluateUrlSecurity(rawUrl) {
  if (!rawUrl || !rawUrl.startsWith('http')) {
    return { riskLevel: 'internal', title: 'Página Interna / Sistema', hostname: '', isSecure: true };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { riskLevel: 'danger', title: 'URL Malformada', hostname: '', isSecure: false };
  }

  const hostname = parsed.hostname.toLowerCase();
  const isSecureProtocol = parsed.protocol === 'https:';

  // 1. Verificación FQDN estricta (Estándar RFC 3986)
  if (!isValidFqdn(hostname)) {
    return {
      riskLevel: 'danger',
      title: 'Dominio Incompleto o Inválido (Sin TLD)',
      description: `La dirección "${hostname}" carece de extensión de dominio válida (ej. sin .com) y es rechazada por el escudo.`,
      hostname,
      baseDomain: hostname,
      isSecure: false,
    };
  }

  // 2. Detección de homógrafos
  const isPunycode = hostname.includes('xn--');
  const foundChars = [];
  for (const char of hostname) {
    if (CONFUSABLES[char]) foundChars.push(CONFUSABLES[char]);
  }
  const isHomoglyph = isPunycode || foundChars.length > 0;

  if (isHomoglyph) {
    return {
      riskLevel: 'danger',
      title: 'Ataque Homográfico Detectado',
      description: isPunycode
        ? 'El sitio web usa codificación internacional Punycode (xn--) para ocultar caracteres engañosos.'
        : `El dominio contiene caracteres no latinos confusables: ${[...new Set(foundChars)].join(', ')}`,
      hostname,
      baseDomain: extractBaseDomain(hostname),
      isSecure: isSecureProtocol,
    };
  }

  // 3. Detección de Typosquatting, Compound Phishing y TLD Spoofing
  const baseDomain = extractBaseDomain(hostname);
  const userStem = baseDomain.split('.')[0];
  const userTld = baseDomain.split('.').slice(1).join('.');

  for (const target of POPULAR_TARGETS) {
    const targetBase = extractBaseDomain(target);
    const targetStem = targetBase.split('.')[0];
    const targetTld = targetBase.split('.').slice(1).join('.');

    if (baseDomain === targetBase) continue;

    // TLD Spoofing
    if (userStem === targetStem && userTld !== targetTld) {
      return {
        riskLevel: 'danger',
        title: 'Extensión No Autorizada (TLD Spoofing)',
        description: `El dominio "${baseDomain}" intenta suplantar el servicio oficial "${target}" con una extensión no autorizada (.${userTld}).`,
        hostname,
        baseDomain,
        target,
        isSecure: isSecureProtocol,
      };
    }

    // Compound Phishing
    if (
      userStem !== targetStem &&
      (userStem.includes(targetStem) || userStem.startsWith(targetStem + '-') || userStem.endsWith('-' + targetStem))
    ) {
      return {
        riskLevel: 'danger',
        title: 'Suplantación de Marca (Compound Phishing)',
        description: `El dominio "${baseDomain}" imita la marca oficial "${target}" con palabras clave engañosas.`,
        hostname,
        baseDomain,
        target,
        isSecure: isSecureProtocol,
      };
    }

    // Levenshtein & visual substitutions
    const dist = calculateLevenshtein(userStem, targetStem);
    const normDist = calculateLevenshtein(normalizeSubstitutions(userStem), normalizeSubstitutions(targetStem));

    if (dist <= 2 || normDist <= 2 || (targetStem.length >= 6 && dist <= 3 && userStem.startsWith(targetStem.slice(0, 2)))) {
      return {
        riskLevel: 'danger',
        title: 'Posible Typosquatting / Suplantación',
        description: `El dominio "${baseDomain}" es similar al servicio oficial "${target}". Podría ser un clon de phishing.`,
        hostname,
        baseDomain,
        target,
        isSecure: isSecureProtocol,
      };
    }
  }

  // 4. Verificación de HTTP inseguro
  if (!isSecureProtocol && hostname !== 'localhost' && hostname !== '127.0.0.1') {
    return {
      riskLevel: 'warning',
      title: 'Conexión Insegura (HTTP)',
      description: 'El sitio no utiliza cifrado HTTPS. Tus credenciales podrían ser interceptadas en la red.',
      hostname,
      baseDomain,
      isSecure: false,
    };
  }

  return {
    riskLevel: 'safe',
    title: 'Dominio Verificado',
    description: 'Conexión HTTPS segura y sin patrones de suplantación detectados.',
    hostname,
    baseDomain,
    isSecure: true,
  };
}

async function analyzeAndProtectTab(tabId, url) {
  if (!url) return;
  const assessment = evaluateUrlSecurity(url);

  // Almacenar diagnóstico para el popup
  await chrome.storage.local.set({ [`tab_${tabId}`]: assessment });

  // Actualizar indicador visual en el icono de la extensión
  if (assessment.riskLevel === 'danger') {
    chrome.action.setBadgeText({ text: '!', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
    try {
      chrome.tabs.sendMessage(tabId, { action: 'PHISHING_ALERT', data: assessment });
    } catch {
      // Ignorar si el content script aún no está listo
    }
  } else if (assessment.riskLevel === 'warning') {
    chrome.action.setBadgeText({ text: 'HTTP', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
  } else if (assessment.riskLevel === 'safe') {
    // Si hay credenciales guardadas para este sitio, mostrar cantidad como 1Password / Bitwarden
    const matches = await findMatchingCredentialsForUrl(url);
    if (matches.length > 0) {
      chrome.action.setBadgeText({ text: String(matches.length), tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#2563eb', tabId });
    } else {
      chrome.action.setBadgeText({ text: '✓', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId });
    }
  } else {
    chrome.action.setBadgeText({ text: '', tabId });
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    analyzeAndProtectTab(tabId, tab.url);

    if (tab.url.includes('localhost:5173') || tab.url.includes('127.0.0.1:5173')) {
      try {
        if (chrome.scripting) {
          const results = await chrome.scripting.executeScript({
            target: { tabId },
            func: () => window.__ARCA_VAULT_ITEMS__ || null,
          });
          const items = results?.[0]?.result;
          if (Array.isArray(items) && items.length > 0) {
            await chrome.storage.local.set({ arca_vault_items: items });
          }
        }
      } catch {}
    }
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab && tab.url) {
    analyzeAndProtectTab(activeInfo.tabId, tab.url);

    if (tab.url.includes('localhost:5173') || tab.url.includes('127.0.0.1:5173')) {
      try {
        if (chrome.scripting) {
          const results = await chrome.scripting.executeScript({
            target: { tabId: activeInfo.tabId },
            func: () => window.__ARCA_VAULT_ITEMS__ || null,
          });
          const items = results?.[0]?.result;
          if (Array.isArray(items) && items.length > 0) {
            await chrome.storage.local.set({ arca_vault_items: items });
          }
        }
      } catch {}
    }
  }
});

/**
 * Extrae la marca u organización principal del dominio o URL,
 * descartando prefijos técnicos de autenticación (keycloak, auth, login, accounts, sso, etc.)
 * y extensiones territoriales compuestas (.com.ve, .com.co, etc.).
 */
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

/**
 * Obtiene las credenciales activas almacenadas de forma segura en la sesión del navegador.
 * Evita la pérdida de datos cuando el Service Worker se suspende en Manifest V3.
 */
async function getStoredVaultItems() {
  try {
    const data = await chrome.storage.local.get('arca_vault_items');
    return Array.isArray(data.arca_vault_items) ? data.arca_vault_items : [];
  } catch {
    return [];
  }
}

/**
 * Busca credenciales que coincidan con la URL dada por dominio base, marca, subdominio o título.
 * Soporta plataformas SSO (Keycloak, Google Accounts, Microsoft), dominios territoriales (.com.ve)
 * y coincidencias de título.
 */
async function findMatchingCredentialsForUrl(tabUrl) {
  if (!tabUrl) return [];
  const items = await getStoredVaultItems();
  if (items.length === 0) return [];

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

          // Coincidencia exacta de base o sufijo
          if (itemBase === tabBase || tabHost.endsWith(itemHost) || itemHost.endsWith(tabHost)) {
            return true;
          }

          // Coincidencia por marca entre dominios de distinto TLD (ej. cinesunidos.com <-> cinesunidos.com.ve)
          if (tabBrand && itemBrand && tabBrand.length >= 3 && tabBrand === itemBrand) {
            return true;
          }

          return false;
        } catch {
          return false;
        }
      });
      if (urlMatched) return true;
    }

    // 2. Coincidencia por título (ej. Título "Cines Unidos" coincide con "cinesunidos.com" o "/realms/cinesunidos")
    if (item.title && typeof item.title === 'string') {
      const cleanTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (cleanTitle.length >= 3) {
        if (tabBrand && (cleanTitle.includes(tabBrand) || tabBrand.includes(cleanTitle))) {
          return true;
        }
        const cleanTabBase = tabBase.split('.')[0].replace(/[^a-z0-9]/g, '');
        if (cleanTitle.includes(cleanTabBase) || cleanTabBase.includes(cleanTitle)) {
          return true;
        }
        // Buscar palabras del título en la ruta SSO (ej. /realms/cinesunidos/)
        if (tabPath.includes(cleanTitle)) {
          return true;
        }
      }
    }

    return false;
  });
}

const tabLastFilled = new Map();

chrome.tabs.onRemoved?.addListener((tabId) => {
  tabLastFilled.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'SET_LAST_FILLED') {
    const tabId = sender.tab?.id;
    if (tabId && request.credential) {
      tabLastFilled.set(tabId, { ...request.credential, timestamp: Date.now() });
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.action === 'GET_LAST_FILLED') {
    const tabId = sender.tab?.id;
    const cached = tabId ? tabLastFilled.get(tabId) : null;
    if (cached && Date.now() - cached.timestamp < 300000) {
      sendResponse({ credential: cached });
    } else {
      sendResponse({ credential: null });
    }
    return true;
  }

  if (request.action === 'GET_CURRENT_SECURITY_REPORT') {
    const targetUrl = request.url || sender.tab?.url;
    if (targetUrl) {
      sendResponse(evaluateUrlSecurity(targetUrl));
      return true;
    }

    chrome.tabs.query({ active: true, lastFocusedWindow: true }, async (tabs) => {
      const tab = (tabs && tabs[0]) || (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
      if (tab) {
        const data = await chrome.storage.local.get(`tab_${tab.id}`);
        sendResponse(data[`tab_${tab.id}`] || evaluateUrlSecurity(tab.url));
      } else {
        sendResponse(null);
      }
    });
    return true; // Asíncrono
  }

  if (request.action === 'SAVE_VAULT_ITEMS') {
    const items = Array.isArray(request.items) ? request.items : [];
    chrome.storage.local.set({ arca_vault_items: items }, async () => {
      sendResponse({ success: true, count: items.length });
      // Actualizar insignia en la pestaña activa
      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs[0] && tabs[0].url) {
          analyzeAndProtectTab(tabs[0].id, tabs[0].url);
        }
      } catch {}
    });
    return true;
  }

  if (request.action === 'CLEAR_VAULT_ITEMS') {
    chrome.storage.local.remove('arca_vault_items', () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.action === 'GET_ALL_VAULT_ITEMS') {
    getStoredVaultItems().then((items) => {
      sendResponse({
        items: items.map((m) => ({
          id: m.id,
          title: m.title,
          username: m.username,
          password: m.password,
          urls: m.urls,
        })),
      });
    });
    return true;
  }

  if (request.action === 'GET_MATCHING_CREDENTIALS') {
    const tabUrl = request.url || sender.tab?.url;
    if (!tabUrl) {
      sendResponse({ matches: [], blocked: false });
      return true;
    }

    const assessment = evaluateUrlSecurity(tabUrl);
    // REGLA CRÍTICA DE CIBERSEGURIDAD: Si el sitio es sospechoso o de phishing, nunca entregar credenciales
    if (assessment.riskLevel === 'danger' || assessment.riskLevel === 'warning') {
      sendResponse({
        matches: [],
        blocked: true,
        riskLevel: assessment.riskLevel,
        threatTitle: assessment.title,
      });
      return true;
    }

    findMatchingCredentialsForUrl(tabUrl).then((matches) => {
      sendResponse({
        matches: matches.map((m) => ({
          id: m.id,
          title: m.title,
          username: m.username,
          password: m.password,
        })),
        blocked: false,
      });
    });
    return true;
  }
});


