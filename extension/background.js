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
    // Notificar al content script para bloquear autocompletado y mostrar alerta flotante
    try {
      chrome.tabs.sendMessage(tabId, { action: 'PHISHING_ALERT', data: assessment });
    } catch {
      // Ignorar si el content script aún no está listo
    }
  } else if (assessment.riskLevel === 'warning') {
    chrome.action.setBadgeText({ text: 'HTTP', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
  } else if (assessment.riskLevel === 'safe') {
    chrome.action.setBadgeText({ text: '✓', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId });
  } else {
    chrome.action.setBadgeText({ text: '', tabId });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    analyzeAndProtectTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab && tab.url) {
    analyzeAndProtectTab(activeInfo.tabId, tab.url);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GET_CURRENT_SECURITY_REPORT') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0]) {
        const data = await chrome.storage.local.get(`tab_${tabs[0].id}`);
        sendResponse(data[`tab_${tabs[0].id}`] || evaluateUrlSecurity(tabs[0].url));
      } else {
        sendResponse(null);
      }
    });
    return true; // Asíncrono
  }
});
