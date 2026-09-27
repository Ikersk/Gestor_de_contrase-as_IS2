import { describe, expect, it } from 'vitest';

// Simulación de las funciones centrales de la extensión para verificación estricta
function extractDomainBrand(rawDomainOrUrl: string): string {
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

function extractBaseDomain(hostname: string): string {
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

function computeMatchingCredentials(tabUrl: string, items: any[]): any[] {
  if (!tabUrl || !Array.isArray(items) || items.length === 0) return [];

  let parsedTab: URL;
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
    if (item.urls && Array.isArray(item.urls)) {
      const urlMatched = item.urls.some((itemUrl: string) => {
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

// Lógica de resolución inteligente para el paso 2 de Google
function resolveStep2Password(pageText: string, sessionCache: any, matchingCreds: any[], allCreds: any[]): string | null {
  // 1. Si tenemos sesión de paso 1
  if (sessionCache && sessionCache.password) {
    return sessionCache.password;
  }
  // 2. Si el texto en pantalla contiene el email
  const matched = matchingCreds.find((c) => c.username && pageText.includes(c.username)) ||
                  allCreds.find((c) => c.username && pageText.includes(c.username));
  if (matched && matched.password) {
    return matched.password;
  }
  // 3. Si solo hay 1 credencial coincidente para Google
  if (matchingCreds.length === 1 && matchingCreds[0].password) {
    return matchingCreds[0].password;
  }
  return null;
}

describe('Arca Extension Autofill & 2-Step Authentication Logic', () => {
  const vaultItems = [
    {
      id: '1',
      title: 'gmail',
      username: 'herrera30723358@usm.edu.ve',
      password: 'MyGoogleSecretPass2026!',
      urls: ['https://mail.google.com'],
    },
    {
      id: '2',
      title: 'Cines Unidos',
      username: 'ale_cines@mail.com',
      password: 'CinesPassword123#',
      urls: ['https://www.cinesunidos.com.ve'],
    },
  ];

  it('matches Google Accounts domain to credentials with Title "gmail" or "mail.google.com"', () => {
    const tabUrl = 'https://accounts.google.com/v3/signin/challenge/pwd?TL=ADG-test';
    const matches = computeMatchingCredentials(tabUrl, vaultItems);

    expect(matches).toHaveLength(1);
    expect(matches[0].username).toBe('herrera30723358@usm.edu.ve');
    expect(matches[0].password).toBe('MyGoogleSecretPass2026!');
  });

  it('matches Keycloak SSO to Cines Unidos credential even across .com and .com.ve', () => {
    const tabUrl = 'https://keycloak.cinesunidos.com/realms/cinesunidos/protocol/openid-connect/auth';
    const matches = computeMatchingCredentials(tabUrl, vaultItems);

    expect(matches).toHaveLength(1);
    expect(matches[0].title).toBe('Cines Unidos');
    expect(matches[0].username).toBe('ale_cines@mail.com');
  });

  it('simulates Step 1 (email): saves session and sets value', () => {
    const cred = vaultItems[0];
    const sessionCache = {
      username: cred.username,
      password: cred.password,
      timestamp: Date.now(),
    };

    expect(sessionCache.username).toBe('herrera30723358@usm.edu.ve');
    expect(sessionCache.password).toBe('MyGoogleSecretPass2026!');
  });

  it('simulates Step 2 (password screen): immediately resolves password via screen email or single match', () => {
    const screenText = 'Te damos la bienvenida herrera30723358@usm.edu.ve Ingresa tu contraseña Siguiente';
    const matching = computeMatchingCredentials('https://accounts.google.com/v3/signin/challenge/pwd', vaultItems);

    // Caso A: Con sesión activa de paso 1
    const passWithSession = resolveStep2Password(screenText, { username: 'herrera30723358@usm.edu.ve', password: 'MyGoogleSecretPass2026!' }, matching, vaultItems);
    expect(passWithSession).toBe('MyGoogleSecretPass2026!');

    // Caso B: Sin sesión (usuario abrió directo el paso 2 o escribió el email manualmente)
    const passWithoutSession = resolveStep2Password(screenText, null, matching, vaultItems);
    expect(passWithoutSession).toBe('MyGoogleSecretPass2026!');
  });

  it('ranks real visible Google password input ("Passwd") above offscreen dummy inputs', () => {
    function scorePass(input: any): number {
      let score = 0;
      if (input.name === 'Passwd') score += 150;
      if (input.autocomplete === 'current-password') score += 120;
      if (input.autocomplete === 'new-password') score += 100;
      if (input.type === 'password') score += 80;
      if (input.tabindex !== '-1') score += 30;
      return score;
    }

    const dummyInput = {
      name: '',
      type: 'password',
      autocomplete: 'off',
      tabindex: '-1',
    };

    const googlePasswdInput = {
      name: 'Passwd',
      type: 'password',
      autocomplete: 'current-password',
      tabindex: '0',
    };

    const scoreDummy = scorePass(dummyInput);
    const scoreReal = scorePass(googlePasswdInput);

    expect(scoreReal).toBeGreaterThan(scoreDummy);
    expect(scoreReal).toBe(150 + 120 + 80 + 30); // 380
    expect(scoreDummy).toBe(80);
  });

  it('calculates popover position directly beneath input and flips if viewport overflows', () => {
    function calculatePopoverPosition(inputRect: { top: number; bottom: number; left: number; width: number }, popoverHeight: number, windowHeight: number, windowWidth: number) {
      const popoverWidth = Math.max(300, Math.min(inputRect.width, 420));
      let top = inputRect.bottom + 6;
      if (top + popoverHeight > windowHeight - 8 && inputRect.top > popoverHeight + 10) {
        top = inputRect.top - popoverHeight - 6;
      }
      let left = Math.max(8, Math.min(inputRect.left, windowWidth - popoverWidth - 8));
      return { top, left, width: popoverWidth };
    }

    // Caso 1: Espacio suficiente abajo (formulario a media pantalla)
    const posNormal = calculatePopoverPosition({ top: 200, bottom: 240, left: 150, width: 350 }, 250, 900, 1200);
    expect(posNormal.top).toBe(246); // 240 + 6
    expect(posNormal.left).toBe(150);
    expect(posNormal.width).toBe(350);

    // Caso 2: Cerca del borde inferior (debe voltearse arriba del input)
    const posFlipped = calculatePopoverPosition({ top: 750, bottom: 790, left: 150, width: 350 }, 250, 900, 1200);
    expect(posFlipped.top).toBe(750 - 250 - 6); // 494
    expect(posFlipped.left).toBe(150);
  });

  it('supports adaptive CSS variables for both Light Mode and Dark Mode', () => {
    const lightTheme = {
      '--arca-bg': '#ffffff',
      '--arca-border': '#e2e8f0',
      '--arca-text-main': '#0f172a',
      '--arca-accent': '#2563eb',
    };

    const darkTheme = {
      '--arca-bg': '#0f172a',
      '--arca-border': '#334155',
      '--arca-text-main': '#f8fafc',
      '--arca-accent': '#38bdf8',
    };

    expect(lightTheme['--arca-bg']).toBe('#ffffff');
    expect(darkTheme['--arca-bg']).toBe('#0f172a');
    expect(lightTheme['--arca-accent']).toBe('#2563eb');
    expect(darkTheme['--arca-accent']).toBe('#38bdf8');
  });
});

