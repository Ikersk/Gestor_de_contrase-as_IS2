/**
 * Módulo de Análisis Criptográfico de URLs y Detección de Suplantación (Anti-Phishing Shield)
 * Siguiendo estándares de seguridad RFC 3986 y Public Suffix List.
 *
 * Analiza enlaces guardados y en tiempo real para detectar:
 * 1. Dominios incompletos o sin TLD (Single-label hostnames como "nexfl").
 * 2. Ataques homográficos (Punycode e inyección de caracteres cirílicos/griegos confusables).
 * 3. Typosquatting por sustitución fonética o de teclado (ej. g00gle.com, paypa1.com).
 * 4. Suplantación de marca compuesta (Compound Phishing ej. netflix-login.com).
 * 5. Suplantación de extensión (TLD Spoofing ej. netflix.xyz).
 * 6. Protocolos inseguros (HTTP en texto plano sin cifrado TLS).
 * 7. Distinción entre Servicio Oficial Verificado vs Dominio Personalizado.
 */

export interface UrlSecurityReport {
  url: string;
  hostname: string;
  isSecureProtocol: boolean;
  isHomoglyphAttack: boolean;
  homoglyphDetails?: string;
  isTyposquatting: boolean;
  typosquatTarget?: string;
  isPunycode: boolean;
  isValidFqdn: boolean;
  isOfficialVerified: boolean;
  riskLevel: 'safe' | 'warning' | 'danger';
  threatTitle: string;
  threatDescription?: string;
  canDirectOpen: boolean;
  matchPolicyNote?: string;
}

export interface ProtectedBrand {
  domain: string;
  stem: string;
  aliases: string[];
}

// Catálogo de marcas y servicios de alto impacto protegidos en Arca
export const PROTECTED_BRANDS: ProtectedBrand[] = [
  { domain: 'netflix.com', stem: 'netflix', aliases: ['nexfl', 'netfl', 'netflx', 'neflix', 'nexflix', 'netlfix', 'nexf'] },
  { domain: 'paypal.com', stem: 'paypal', aliases: ['payp', 'paypa1', 'paypol', 'paypall'] },
  { domain: 'google.com', stem: 'google', aliases: ['g00g', 'g00gle', 'googl', 'gogle', 'googel'] },
  { domain: 'accounts.google.com', stem: 'google', aliases: [] },
  { domain: 'microsoft.com', stem: 'microsoft', aliases: ['msft', 'micros0ft', 'microsof'] },
  { domain: 'login.microsoftonline.com', stem: 'microsoft', aliases: [] },
  { domain: 'apple.com', stem: 'apple', aliases: ['aple', 'appIe', 'appl'] },
  { domain: 'amazon.com', stem: 'amazon', aliases: ['amzn', 'amazn', 'amaz0n'] },
  { domain: 'facebook.com', stem: 'facebook', aliases: ['faceb00k', 'facebok', 'fb'] },
  { domain: 'instagram.com', stem: 'instagram', aliases: ['instagrm', 'instagr0m', 'insta'] },
  { domain: 'github.com', stem: 'github', aliases: ['githb', 'githvb', 'g1thub'] },
  { domain: 'twitter.com', stem: 'twitter', aliases: ['twittr', 'twtr'] },
  { domain: 'x.com', stem: 'x', aliases: [] },
  { domain: 'linkedin.com', stem: 'linkedin', aliases: ['linkdn', 'linked1n'] },
  { domain: 'dropbox.com', stem: 'dropbox', aliases: ['drpbox'] },
  { domain: 'spotify.com', stem: 'spotify', aliases: ['spotfy', 'sp0tify'] },
  { domain: 'binance.com', stem: 'binance', aliases: ['binanc', 'binanxe'] },
  { domain: 'coinbase.com', stem: 'coinbase', aliases: ['coinbse', 'c0inbase'] },
  { domain: 'bankofamerica.com', stem: 'bankofamerica', aliases: ['bofa'] },
  { domain: 'chase.com', stem: 'chase', aliases: ['chas'] },
  { domain: 'wellsfargo.com', stem: 'wellsfargo', aliases: ['wellfargo'] },
  { domain: 'santander.com', stem: 'santander', aliases: ['santandr'] },
  { domain: 'bbva.com', stem: 'bbva', aliases: [] },
  { domain: 'mercadolibre.com', stem: 'mercadolibre', aliases: ['mercadolib'] },
  { domain: 'mercadopago.com', stem: 'mercadopago', aliases: ['mercadopag'] },
];

export const POPULAR_TARGETS: string[] = PROTECTED_BRANDS.map((b) => b.domain);

// Mapa de caracteres cirílicos/griegos confusables más usados en ataques IDN Homograph
export const CONFUSABLE_CHARACTERS: Record<string, string> = {
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
  '\u0410': 'A (Cirílico)',
  '\u0412': 'B (Cirílico)',
  '\u0415': 'E (Cirílico)',
  '\u041A': 'K (Cirílico)',
  '\u041C': 'M (Cirílico)',
  '\u041D': 'H (Cirílico)',
  '\u041E': 'O (Cirílico)',
  '\u0420': 'P (Cirílico)',
  '\u0421': 'C (Cirílico)',
  '\u0422': 'T (Cirílico)',
  '\u0425': 'X (Cirílico)',
  '\u03BF': 'o (Griego)',
  '\u03BD': 'v (Griego)',
  '\u03C1': 'p (Griego)',
  '\u03B1': 'a (Griego)',
};

/**
 * Calcula la distancia de Levenshtein (número mínimo de operaciones de edición) entre dos cadenas.
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,       // Eliminación
        dp[i][j - 1] + 1,       // Inserción
        dp[i - 1][j - 1] + cost // Sustitución
      );
    }
  }

  return dp[m][n];
}

/**
 * Normaliza sustituciones visuales comunes de typosquatting como 0->o, 1->l, rn->m, vv->w.
 */
function normalizeVisualSubstitutions(domain: string): string {
  return domain
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

/**
 * Valida si un hostname es un FQDN (Fully Qualified Domain Name) legítimo conforme a estándares RFC.
 * Requiere localhost, IP válida o un dominio con al menos un punto y TLD de 2+ letras.
 */
export function isValidFqdn(hostname: string): boolean {
  const clean = hostname.toLowerCase().trim().replace(/:\d+$/, '');
  if (!clean) return false;
  if (clean === 'localhost') return true;

  // Comprobar dirección IPv4 válida (ej. 127.0.0.1, 192.168.1.10)
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) {
    const octets = clean.split('.').map(Number);
    return octets.every((o) => o >= 0 && o <= 255);
  }

  // Un dominio FQDN debe contener al menos un punto separador
  if (!clean.includes('.')) return false;

  const parts = clean.split('.');
  if (parts.some((p) => p.length === 0)) return false;

  const tld = parts[parts.length - 1];
  // La extensión TLD debe tener entre 2 y 24 caracteres alfabéticos
  return /^[a-z]{2,24}$/i.test(tld);
}

/**
 * Extrae el dominio raíz (eTLD+1) aproximado para comparaciones.
 */
export function extractBaseDomain(hostname: string): string {
  const cleanHost = hostname.toLowerCase().trim().replace(/:\d+$/, '');
  const parts = cleanHost.split('.');
  if (parts.length <= 2) return cleanHost;

  // Manejo de dominios compuestos comunes como .co.uk, .com.mx, .edu.ve
  const secondLevelTlds = ['co', 'com', 'org', 'net', 'edu', 'gob', 'gov'];
  const tld = parts[parts.length - 1];
  const secondTld = parts[parts.length - 2];

  if (parts.length >= 3 && secondLevelTlds.includes(secondTld) && tld.length === 2) {
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}

/**
 * Analiza exhaustivamente una URL siguiendo la política de verificación de dominio base de Arca.
 */
export function analyzeUrl(rawUrl: string): UrlSecurityReport {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      url: rawUrl,
      hostname: '',
      isSecureProtocol: false,
      isHomoglyphAttack: false,
      isTyposquatting: false,
      isPunycode: false,
      isValidFqdn: false,
      isOfficialVerified: false,
      riskLevel: 'danger',
      threatTitle: 'URL Inválida',
      threatDescription: 'La URL proporcionada no es una cadena válida.',
      canDirectOpen: false,
      matchPolicyNote: 'Arca Guard: URL vacía o no válida.',
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
  } catch {
    return {
      url: rawUrl,
      hostname: '',
      isSecureProtocol: false,
      isHomoglyphAttack: false,
      isTyposquatting: false,
      isPunycode: false,
      isValidFqdn: false,
      isOfficialVerified: false,
      riskLevel: 'danger',
      threatTitle: 'Formato Malicioso o Malformado',
      threatDescription: 'La dirección web no cumple con los estándares RFC de direccionamiento URL.',
      canDirectOpen: false,
      matchPolicyNote: 'Arca Guard: Formato no conforme a RFC.',
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.toLowerCase();
  const isSecureProtocol = protocol === 'https:';

  // 1. Verificación FQDN estricta (Estándar RFC 3986)
  const isFqdn = isValidFqdn(hostname);
  if (!isFqdn) {
    // Verificar si el término de etiqueta única coincide o intenta imitar a una marca conocida (ej. "nexfl" -> "netflix.com")
    for (const brand of PROTECTED_BRANDS) {
      const isAlias = brand.aliases.includes(hostname);
      const dist = calculateLevenshteinDistance(hostname, brand.stem);
      const isPrefix = hostname.length >= 4 && brand.stem.startsWith(hostname.slice(0, 3));

      if (isAlias || dist <= 3 || isPrefix) {
        return {
          url: rawUrl,
          hostname,
          isSecureProtocol,
          isHomoglyphAttack: false,
          isTyposquatting: true,
          typosquatTarget: brand.domain,
          isPunycode: false,
          isValidFqdn: false,
          isOfficialVerified: false,
          riskLevel: 'danger',
          threatTitle: `Posible imitación de ${brand.domain}`,
          threatDescription: `La dirección "${hostname}" carece de extensión de dominio válida (sin .com) y coincide con el patrón de imitación o tipeo incompleto de ${brand.domain}. Arca exige nombres de dominio completos (FQDN) para garantizar la navegación segura y prevenir secuestro de resolución.`,
          canDirectOpen: false,
          matchPolicyNote: `Arca Domain Guard: Bloqueado por ausencia de FQDN y coincidencia con ${brand.domain}.`,
        };
      }
    }

    // Dominio incompleto genérico sin TLD
    return {
      url: rawUrl,
      hostname,
      isSecureProtocol,
      isHomoglyphAttack: false,
      isTyposquatting: false,
      isPunycode: false,
      isValidFqdn: false,
      isOfficialVerified: false,
      riskLevel: 'danger',
      threatTitle: 'Dirección Incompleta o Inválida (Sin TLD)',
      threatDescription: `La dirección "${hostname}" no contiene una extensión de dominio pública válida (.com, .org, .net, etc.). Siguiendo las políticas de seguridad de Arca y el estándar RFC 3986, todo acceso web debe tener un nombre de dominio completo (FQDN) para evitar ambigüedades y errores de resolución.`,
      canDirectOpen: false,
      matchPolicyNote: 'Arca Domain Guard: FQDN requerido.',
    };
  }

  // 2. Detección de Punycode (IDN) y Homógrafos
  const isPunycode = hostname.includes('xn--');
  const foundConfusables: string[] = [];
  for (const char of hostname) {
    if (CONFUSABLE_CHARACTERS[char]) {
      foundConfusables.push(CONFUSABLE_CHARACTERS[char]);
    }
  }
  const isHomoglyphAttack = isPunycode || foundConfusables.length > 0;
  const homoglyphDetails =
    foundConfusables.length > 0
      ? `Contiene caracteres engañosos: ${[...new Set(foundConfusables)].join(', ')}`
      : isPunycode
      ? 'El dominio utiliza codificación internacional Punycode (xn--), frecuentemente usada para suplantar identidades.'
      : undefined;

  if (isHomoglyphAttack) {
    return {
      url: rawUrl,
      hostname,
      isSecureProtocol,
      isHomoglyphAttack: true,
      homoglyphDetails,
      isTyposquatting: false,
      isPunycode,
      isValidFqdn: true,
      isOfficialVerified: false,
      riskLevel: 'danger',
      threatTitle: 'Ataque Homográfico Detectado (Phishing Crítico)',
      threatDescription: `El dominio utiliza caracteres de otros alfabetos diseñados para engañar visualmente al usuario imitando un sitio legítimo. ${homoglyphDetails}`,
      canDirectOpen: false,
      matchPolicyNote: 'Arca Domain Guard: Bloqueo estricto por colisión de homógrafo IDN.',
    };
  }

  // 3. Verificación de Marcas Oficiales vs Typosquatting / Compound Phishing / TLD Spoofing
  const baseDomain = extractBaseDomain(hostname);
  const userStem = baseDomain.split('.')[0];
  const userTld = baseDomain.split('.').slice(1).join('.');

  for (const brand of PROTECTED_BRANDS) {
    const officialBase = extractBaseDomain(brand.domain);
    const officialStem = brand.stem;
    const officialTld = officialBase.split('.').slice(1).join('.');

    // A. Es el dominio oficial legítimo (ej. netflix.com, www.netflix.com, accounts.google.com)
    if (baseDomain === officialBase || hostname === brand.domain || hostname.endsWith('.' + brand.domain)) {
      if (!isSecureProtocol) {
        return {
          url: rawUrl,
          hostname,
          isSecureProtocol: false,
          isHomoglyphAttack: false,
          isTyposquatting: false,
          isPunycode,
          isValidFqdn: true,
          isOfficialVerified: true,
          riskLevel: 'warning',
          threatTitle: `Conexión Insegura (HTTP en servicio oficial ${brand.domain})`,
          threatDescription: `El dominio pertenece a ${brand.domain}, pero no utiliza HTTPS. Arca alerta que tus credenciales viajarían en texto plano en la red.`,
          canDirectOpen: false,
          matchPolicyNote: `Arca Match: Dominio Base Oficial (${brand.domain})`,
        };
      }
      return {
        url: rawUrl,
        hostname,
        isSecureProtocol: true,
        isHomoglyphAttack: false,
        isTyposquatting: false,
        isPunycode,
        isValidFqdn: true,
        isOfficialVerified: true,
        riskLevel: 'safe',
        threatTitle: `Servicio Oficial Verificado (${brand.domain})`,
        threatDescription: `Dominio oficial verificado con cifrado TLS activo. Cumple con la política de verificación de dominio base oficial.`,
        canDirectOpen: true,
        matchPolicyNote: `Arca Match: Dominio Base Oficial (${brand.domain})`,
      };
    }

    // B. Suplantación de Extensión (TLD Spoofing)
    // Ej: netflix.xyz, netflix.top, paypal.cc
    if (userStem === officialStem && userTld !== officialTld) {
      return {
        url: rawUrl,
        hostname,
        isSecureProtocol,
        isHomoglyphAttack: false,
        isTyposquatting: true,
        typosquatTarget: brand.domain,
        isPunycode,
        isValidFqdn: true,
        isOfficialVerified: false,
        riskLevel: 'danger',
        threatTitle: 'Extensión No Autorizada de Marca (TLD Spoofing)',
        threatDescription: `El dominio "${baseDomain}" utiliza la marca "${officialStem}" con una extensión no autorizada (.${userTld}) en lugar de la oficial (.${officialTld}).`,
        canDirectOpen: false,
        matchPolicyNote: `Arca Match: TLD no coincide con el dominio oficial ${brand.domain}.`,
      };
    }

    // C. Suplantación de Marca Compuesta (Compound Phishing)
    // Ej: netflix-login.com, netflix-billing.org, verify-paypal.com, google-support.com
    if (
      userStem !== officialStem &&
      (userStem.includes(officialStem) ||
        userStem.startsWith(officialStem + '-') ||
        userStem.endsWith('-' + officialStem))
    ) {
      return {
        url: rawUrl,
        hostname,
        isSecureProtocol,
        isHomoglyphAttack: false,
        isTyposquatting: true,
        typosquatTarget: brand.domain,
        isPunycode,
        isValidFqdn: true,
        isOfficialVerified: false,
        riskLevel: 'danger',
        threatTitle: 'Suplantación de Marca Detectada (Compound Phishing)',
        threatDescription: `El dominio "${baseDomain}" incluye la marca oficial "${brand.domain}" combinada con términos señuelo. Arca bloquea estas direcciones para evitar trampas de ingeniería social.`,
        canDirectOpen: false,
        matchPolicyNote: `Arca Match: Rechazado por colisión eTLD+1 fraudulenta con ${brand.domain}.`,
      };
    }

    // D. Alias conocidos o similitud de Levenshtein
    const normUserStem = normalizeVisualSubstitutions(userStem);
    const normOfficialStem = normalizeVisualSubstitutions(officialStem);
    const dist = calculateLevenshteinDistance(normUserStem, normOfficialStem);
    const rawDist = calculateLevenshteinDistance(userStem, officialStem);
    const isAlias = brand.aliases.includes(userStem);

    if (
      isAlias ||
      dist <= 2 ||
      rawDist <= 2 ||
      (officialStem.length >= 6 && dist <= 3 && normUserStem.startsWith(normOfficialStem.slice(0, 2)))
    ) {
      return {
        url: rawUrl,
        hostname,
        isSecureProtocol,
        isHomoglyphAttack: false,
        isTyposquatting: true,
        typosquatTarget: brand.domain,
        isPunycode,
        isValidFqdn: true,
        isOfficialVerified: false,
        riskLevel: 'danger',
        threatTitle: `Posible imitación de ${brand.domain}`,
        threatDescription: `El dominio "${baseDomain}" es sospechosamente similar al servicio oficial "${brand.domain}". Por directriz de seguridad de Arca, se bloquea el almacenamiento y autocompletado en dominios similares para prevenir robo de credenciales.`,
        canDirectOpen: false,
        matchPolicyNote: `Arca Match: Bloqueado por distancia fonética/teclado hacia ${brand.domain}.`,
      };
    }
  }

  // 4. Conexión Insegura (HTTP en texto plano)
  if (!isSecureProtocol) {
    return {
      url: rawUrl,
      hostname,
      isSecureProtocol: false,
      isHomoglyphAttack: false,
      isTyposquatting: false,
      isPunycode,
      isValidFqdn: true,
      isOfficialVerified: false,
      riskLevel: 'warning',
      threatTitle: 'Conexión Insegura (HTTP sin cifrado)',
      threatDescription:
        'Esta dirección no utiliza HTTPS. Cualquier dato enviado o recibido puede ser interceptado o modificado por intermediarios en la red (MitM).',
      canDirectOpen: false,
      matchPolicyNote: 'Arca Warning: Conexión en texto plano no recomendada.',
    };
  }

  // 5. Dominio Personalizado Válido con HTTPS (FQDN verificado pero fuera del catálogo oficial)
  return {
    url: rawUrl,
    hostname,
    isSecureProtocol: true,
    isHomoglyphAttack: false,
    isTyposquatting: false,
    isPunycode,
    isValidFqdn: true,
    isOfficialVerified: false,
    riskLevel: 'safe',
    threatTitle: 'Conexión HTTPS Válida (Dominio Personalizado)',
    threatDescription:
      'Dominio con formato FQDN válido y cifrado TLS activo. (Verificación Arca: Dominio Base Estándar).',
    canDirectOpen: true,
    matchPolicyNote: 'Arca Match: Dominio Base estándar.',
  };
}

/**
 * Implementa la regla de verificación de autocompletado de dominio base:
 * Compara el eTLD+1 del ítem guardado contra el eTLD+1 de la pestaña actual.
 * Si no coinciden o si hay signos de suplantación, deniega el autocompletado.
 */
export function matchesAutofillDomain(savedUrl: string, currentUrl: string): {
  allowed: boolean;
  reason: string;
  savedDomain: string;
  currentDomain: string;
} {
  try {
    const savedHost = new URL(savedUrl.startsWith('http') ? savedUrl : `https://${savedUrl}`).hostname.toLowerCase();
    const currentHost = new URL(currentUrl.startsWith('http') ? currentUrl : `https://${currentUrl}`).hostname.toLowerCase();
    const savedBase = extractBaseDomain(savedHost);
    const currentBase = extractBaseDomain(currentHost);

    // Si la URL actual es riesgosa, bloquea de inmediato
    const currentReport = analyzeUrl(currentUrl);
    if (currentReport.riskLevel === 'danger') {
      return {
        allowed: false,
        reason: `Bloqueado por Arca Shield: La página actual "${currentHost}" ha sido identificada como fraudulenta (${currentReport.threatTitle}).`,
        savedDomain: savedBase,
        currentDomain: currentBase,
      };
    }

    if (savedBase === currentBase) {
      return {
        allowed: true,
        reason: `Coincidencia de Dominio Base aprobada (${savedBase}). Autocompletado seguro permitido.`,
        savedDomain: savedBase,
        currentDomain: currentBase,
      };
    }

    return {
      allowed: false,
      reason: `Bloqueado por Arca Shield: El dominio de la pestaña (${currentBase}) no coincide con la dirección guardada en la credencial (${savedBase}).`,
      savedDomain: savedBase,
      currentDomain: currentBase,
    };
  } catch {
    return {
      allowed: false,
      reason: 'URL inválida o no analizable.',
      savedDomain: '',
      currentDomain: '',
    };
  }
}
