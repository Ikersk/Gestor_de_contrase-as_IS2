import { describe, expect, it } from 'vitest';
import {
  analyzeUrl,
  calculateLevenshteinDistance,
  extractBaseDomain,
  isValidFqdn,
  matchesAutofillDomain,
} from './anti-phishing';

describe('Módulo Anti-Phishing y Análisis Criptográfico de URLs (Estándar Arca)', () => {
  describe('Extracción de dominio base (eTLD+1)', () => {
    it('extrae dominios estándar simples y con subdominios', () => {
      expect(extractBaseDomain('google.com')).toBe('google.com');
      expect(extractBaseDomain('accounts.google.com')).toBe('google.com');
      expect(extractBaseDomain('auth.service.paypal.com')).toBe('paypal.com');
    });

    it('maneja correctamente dominios con extensiones de segundo nivel compuestas', () => {
      expect(extractBaseDomain('portal.banco.com.mx')).toBe('banco.com.mx');
      expect(extractBaseDomain('service.amazon.co.uk')).toBe('amazon.co.uk');
      expect(extractBaseDomain('facultad.usm.edu.ve')).toBe('usm.edu.ve');
    });
  });

  describe('Validación FQDN y Extensiones TLD (RFC 3986)', () => {
    it('valida nombres de dominio completos con TLD', () => {
      expect(isValidFqdn('netflix.com')).toBe(true);
      expect(isValidFqdn('google.es')).toBe(true);
      expect(isValidFqdn('localhost')).toBe(true);
      expect(isValidFqdn('127.0.0.1')).toBe(true);
    });

    it('rechaza dominios incompletos o de etiqueta única sin TLD', () => {
      expect(isValidFqdn('nexfl')).toBe(false);
      expect(isValidFqdn('netflix')).toBe(false);
      expect(isValidFqdn('miempresa')).toBe(false);
      expect(isValidFqdn('')).toBe(false);
    });
  });

  describe('Cálculo de Distancia de Levenshtein', () => {
    it('calcula la distancia exacta de operaciones de edición', () => {
      expect(calculateLevenshteinDistance('paypal', 'paypal')).toBe(0);
      expect(calculateLevenshteinDistance('paypal', 'paypa1')).toBe(1);
      expect(calculateLevenshteinDistance('google', 'g00gle')).toBe(2);
      expect(calculateLevenshteinDistance('github', 'gitlab')).toBe(2);
      expect(calculateLevenshteinDistance('paypal', 'payphone')).toBe(4);
    });
  });

  describe('Detección de Ataques Homográficos (Punycode y Cirílico)', () => {
    it('detecta caracteres cirílicos que imitan letras latinas (ej. "а" cirílica en paypal)', () => {
      const fakeUrl = 'https://p\u0430ypal.com/login';
      const report = analyzeUrl(fakeUrl);

      expect(report.isHomoglyphAttack).toBe(true);
      expect(report.riskLevel).toBe('danger');
      expect(report.canDirectOpen).toBe(false);
      expect(report.threatTitle).toContain('Ataque Homográfico');
    });

    it('detecta URLs con codificación internacional Punycode (xn--)', () => {
      const punycodeUrl = 'https://xn--pypal-4ve.com/signin';
      const report = analyzeUrl(punycodeUrl);

      expect(report.isPunycode).toBe(true);
      expect(report.isHomoglyphAttack).toBe(true);
      expect(report.riskLevel).toBe('danger');
      expect(report.canDirectOpen).toBe(false);
    });
  });

  describe('Detección de Dominios Incompletos y Vulnerabilidades de Tipeo (ej. nexfl)', () => {
    it('bloquea "https://nexfl" como peligroso e identifica que imita a netflix.com', () => {
      const report = analyzeUrl('https://nexfl');
      expect(report.riskLevel).toBe('danger');
      expect(report.isValidFqdn).toBe(false);
      expect(report.isTyposquatting).toBe(true);
      expect(report.typosquatTarget).toBe('netflix.com');
      expect(report.canDirectOpen).toBe(false);
      expect(report.threatTitle).toContain('Posible imitación de netflix.com');
    });

    it('bloquea "https://miempresa" por carecer de extensión TLD válida', () => {
      const report = analyzeUrl('https://miempresa');
      expect(report.riskLevel).toBe('danger');
      expect(report.isValidFqdn).toBe(false);
      expect(report.threatTitle).toContain('Sin TLD');
      expect(report.canDirectOpen).toBe(false);
    });
  });

  describe('Detección de Typosquatting contra servicios oficiales', () => {
    it('detecta sustitución visual numérica en g00gle.com', () => {
      const report = analyzeUrl('https://g00gle.com/search');
      expect(report.isTyposquatting).toBe(true);
      expect(report.typosquatTarget).toBe('google.com');
      expect(report.riskLevel).toBe('danger');
      expect(report.canDirectOpen).toBe(false);
    });

    it('detecta paypa1.com como intento de suplantación de paypal.com', () => {
      const report = analyzeUrl('https://paypa1.com/myaccount');
      expect(report.isTyposquatting).toBe(true);
      expect(report.typosquatTarget).toBe('paypal.com');
      expect(report.riskLevel).toBe('danger');
      expect(report.canDirectOpen).toBe(false);
    });

    it('detecta faceb00k.com como suplantación de facebook.com', () => {
      const report = analyzeUrl('https://faceb00k.com/login');
      expect(report.isTyposquatting).toBe(true);
      expect(report.typosquatTarget).toBe('facebook.com');
      expect(report.riskLevel).toBe('danger');
      expect(report.canDirectOpen).toBe(false);
    });

    it('detecta nexfl.com y nexflix.com como suplantación de netflix.com', () => {
      const report1 = analyzeUrl('https://nexfl.com/watch');
      expect(report1.isTyposquatting).toBe(true);
      expect(report1.typosquatTarget).toBe('netflix.com');
      expect(report1.riskLevel).toBe('danger');

      const report2 = analyzeUrl('https://nexflix.com/browse');
      expect(report2.isTyposquatting).toBe(true);
      expect(report2.typosquatTarget).toBe('netflix.com');
      expect(report2.riskLevel).toBe('danger');
    });

    it('detecta suplantación de marca compuesta (Compound Phishing ej. netflix-login.com)', () => {
      const report = analyzeUrl('https://netflix-login.com/auth');
      expect(report.isTyposquatting).toBe(true);
      expect(report.typosquatTarget).toBe('netflix.com');
      expect(report.riskLevel).toBe('danger');
      expect(report.threatTitle).toContain('Compound Phishing');
    });

    it('detecta suplantación de extensión TLD (TLD Spoofing ej. netflix.xyz)', () => {
      const report = analyzeUrl('https://netflix.xyz/account');
      expect(report.isTyposquatting).toBe(true);
      expect(report.typosquatTarget).toBe('netflix.com');
      expect(report.riskLevel).toBe('danger');
      expect(report.threatTitle).toContain('TLD Spoofing');
    });
  });

  describe('Evaluación de Protocolo Inseguro (HTTP)', () => {
    it('marca advertencia de riesgo para enlaces que no utilizan HTTPS', () => {
      const report = analyzeUrl('http://mi-portal-bancario.com/login');
      expect(report.isSecureProtocol).toBe(false);
      expect(report.riskLevel).toBe('warning');
      expect(report.canDirectOpen).toBe(false);
      expect(report.threatTitle).toContain('Conexión Insegura');
    });
  });

  describe('URLs legítimas y distinción de confianza (Modelo de Confianza)', () => {
    it('certifica como Oficial Verificado URLs auténticas de marcas del catálogo', () => {
      const officialGithub = analyzeUrl('https://github.com/Ikersk/Gestor_de_contrase-as_IS2');
      expect(officialGithub.riskLevel).toBe('safe');
      expect(officialGithub.isSecureProtocol).toBe(true);
      expect(officialGithub.isOfficialVerified).toBe(true);
      expect(officialGithub.canDirectOpen).toBe(true);

      const officialGoogle = analyzeUrl('https://accounts.google.com/signin/v2');
      expect(officialGoogle.riskLevel).toBe('safe');
      expect(officialGoogle.isOfficialVerified).toBe(true);

      const officialNetflix = analyzeUrl('https://www.netflix.com/browse');
      expect(officialNetflix.riskLevel).toBe('safe');
      expect(officialNetflix.isOfficialVerified).toBe(true);
    });

    it('clasifica dominios legítimos externos como Dominio Personalizado Válido sin falsas certezas', () => {
      const customDomain = analyzeUrl('https://miempresalocal.com/app');
      expect(customDomain.riskLevel).toBe('safe');
      expect(customDomain.isValidFqdn).toBe(true);
      expect(customDomain.isOfficialVerified).toBe(false);
      expect(customDomain.threatTitle).toContain('Dominio Personalizado');
    });
  });

  describe('Falsos positivos: dominios legítimos que no deben bloquearse', () => {
    it('certifica twitch.tv como oficial y no lo confunde con twitter.com', () => {
      const report = analyzeUrl('https://www.twitch.tv/directory');
      expect(report.riskLevel).toBe('safe');
      expect(report.isOfficialVerified).toBe(true);
      expect(report.isTyposquatting).toBe(false);
      expect(report.canDirectOpen).toBe(true);
    });

    it('no marca dominios legítimos como imitación de otra marca', () => {
      const legitUrls = [
        'https://dropbox.com/home',
        'https://box.com/login',
        'https://max.com/watch',
        'https://xbox.com/es',
        'https://gitlab.com/explore',
        'https://googleapis.com',
        'https://googletagmanager.com',
        'https://googlemail.com',
        'https://pineapple.com',
        'https://chats.com',
        'https://reddit.com',
        'https://zoom.us',
        'https://notion.so',
        'https://slack.com',
        'https://mi-portal-bancario.com/login',
      ];

      for (const url of legitUrls) {
        const report = analyzeUrl(url);
        expect(report.riskLevel, `${url} -> ${report.threatTitle}`).not.toBe('danger');
        expect(report.isTyposquatting).toBe(false);
      }
    });

    it('sigue detectando typosquatting real y señuelos de marca', () => {
      const dangerousUrls = [
        'https://twich.tv',
        'https://twtch.tv',
        'https://twitchh.tv',
        'https://twitch-login.com',
        'https://netfilx.com',
        'https://netfilx-login.com',
        'https://netflixlogin.com',
        'https://paypal-secure.com',
        'https://verifypaypal.com',
        'https://twitter-login.com',
        'https://x-login.com',
        'https://google-support.com',
        'https://twitch.xyz',
      ];

      for (const url of dangerousUrls) {
        const report = analyzeUrl(url);
        expect(report.riskLevel, `${url} -> ${report.threatTitle}`).toBe('danger');
        expect(report.isTyposquatting).toBe(true);
        expect(report.canDirectOpen).toBe(false);
      }
    });
  });

  describe('Reglas de Autocompletado Seguro (matchesAutofillDomain)', () => {
    it('permite autocompletado si los dominios base coinciden (eTLD+1 match)', () => {
      const result = matchesAutofillDomain(
        'https://accounts.google.com',
        'https://myaccount.google.com/security'
      );
      expect(result.allowed).toBe(true);
      expect(result.savedDomain).toBe('google.com');
      expect(result.currentDomain).toBe('google.com');
    });

    it('bloquea autocompletado si el dominio del navegador difiere del guardado', () => {
      const result = matchesAutofillDomain(
        'https://netflix.com',
        'https://netflix-login.com'
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Bloqueado');
    });

    it('bloquea autocompletado en páginas identificadas con riesgo crítico de phishing', () => {
      const result = matchesAutofillDomain(
        'https://google.com',
        'https://g00gle.com'
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('fraudulenta');
    });
  });
});
