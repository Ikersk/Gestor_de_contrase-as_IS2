import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearVault, installExtensionBridge, publishVault, toExtensionItems } from './extension-bridge';
import type { ExtensionVaultItem } from './extension-bridge';

const contentScriptPath = fileURLToPath(new URL('../../extension/content_script.js', import.meta.url));
const backgroundPath = fileURLToPath(new URL('../../extension/background.js', import.meta.url));
const popupPath = fileURLToPath(new URL('../../extension/popup/popup.js', import.meta.url));

const contentScriptSource = readFileSync(contentScriptPath, 'utf8');
const backgroundSource = readFileSync(backgroundPath, 'utf8');
const popupSource = readFileSync(popupPath, 'utf8');

/** Instala una ventana simulada para ejercitar el puente sin DOM real. */
function installFakeWindow(origin = 'http://localhost:5173') {
  const posted: any[] = [];
  const listeners = new Map<string, Set<(event: any) => void>>();

  const fakeWindow = {
    location: { origin },
    postMessage: (data: any) => posted.push(data),
    addEventListener: (type: string, handler: (event: any) => void) => {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)!.add(handler);
    },
    removeEventListener: (type: string, handler: (event: any) => void) => {
      listeners.get(type)?.delete(handler);
    },
  };

  (globalThis as any).window = fakeWindow;
  return { fakeWindow, posted, listeners };
}

afterEach(() => {
  delete (globalThis as any).window;
  vi.restoreAllMocks();
});

describe('Puente de sincronización bóveda → extensión (Zero-Knowledge)', () => {
  it('solo publica los campos que la extensión necesita y nunca el secreto TOTP', () => {
    const items = toExtensionItems([
      {
        id: 7,
        title: 'Cines Unidos',
        username: 'ale_cines@mail.com',
        password: 'CinesPassword123#',
        urls: [' https://www.cinesunidos.com.ve ', '', 'keycloak.cinesunidos.com'],
        totpSecret: 'JBSWY3DPEHPK3PXP',
        favorite: true,
      } as unknown as ExtensionVaultItem,
    ]);

    expect(items).toEqual([
      {
        id: 7,
        title: 'Cines Unidos',
        username: 'ale_cines@mail.com',
        password: 'CinesPassword123#',
        urls: ['https://www.cinesunidos.com.ve', 'keycloak.cinesunidos.com'],
      },
    ]);
    expect(Object.keys(items[0]).sort()).toEqual(['id', 'password', 'title', 'urls', 'username']);
    expect(JSON.stringify(items)).not.toContain('JBSWY3DPEHPK3PXP');
    expect(JSON.stringify(items)).not.toContain('favorite');
  });

  it('devuelve una lista vacía cuando la entrada no es un arreglo', () => {
    expect(toExtensionItems(null as unknown as ExtensionVaultItem[])).toEqual([]);
    expect(toExtensionItems(undefined as unknown as ExtensionVaultItem[])).toEqual([]);
  });

  it('publica la bóveda desbloqueada y expone el espejo que lee la extensión', () => {
    const { fakeWindow, posted } = installFakeWindow();
    const items = toExtensionItems([
      { id: 1, title: 'gmail', username: 'a@b.com', password: 'secret', urls: ['https://gmail.com'] },
    ]);

    publishVault(items);

    expect((fakeWindow as any).__ARCA_VAULT_ITEMS__).toEqual(items);
    expect(posted).toEqual([{ type: 'ARCA_VAULT_SYNC', credentials: items }]);
  });

  it('publicar una lista vacía equivale a borrar la copia de la extensión', () => {
    const { fakeWindow, posted } = installFakeWindow();
    (fakeWindow as any).__ARCA_VAULT_ITEMS__ = [{ id: 1 }] as ExtensionVaultItem[];

    publishVault([]);

    expect((fakeWindow as any).__ARCA_VAULT_ITEMS__).toBeUndefined();
    expect(posted).toEqual([{ type: 'ARCA_VAULT_CLEAR' }]);
  });

  it('borra el espejo y avisa a la extensión (logout / cierre de pestaña)', () => {
    const { fakeWindow, posted } = installFakeWindow();
    (fakeWindow as any).__ARCA_VAULT_ITEMS__ = [{ id: 1 }] as ExtensionVaultItem[];

    clearVault();

    expect((fakeWindow as any).__ARCA_VAULT_ITEMS__).toBeUndefined();
    expect(posted).toEqual([{ type: 'ARCA_VAULT_CLEAR' }]);
  });

  it('responde a ARCA_REQUEST_SYNC solo con mensajes del mismo origen', () => {
    const { listeners } = installFakeWindow('http://localhost:5173');
    const items = toExtensionItems([
      { id: 1, title: 'gmail', username: 'a@b.com', password: 'secret', urls: [] },
    ]);

    const dispose = installExtensionBridge(() => items);
    const handlers = Array.from(listeners.get('message') ?? []);

    // Mensaje de un origen ajeno: la extensión no debe recibir nada.
    handlers.forEach((handler) => handler({ origin: 'https://evil.example', data: { type: 'ARCA_REQUEST_SYNC' } }));
    expect((globalThis as any).window.__ARCA_VAULT_ITEMS__).toBeUndefined();

    // Mensaje legítimo de la propia pestaña: republica la bóveda.
    handlers.forEach((handler) => handler({ origin: 'http://localhost:5173', data: { type: 'ARCA_REQUEST_SYNC' } }));
    expect((globalThis as any).window.__ARCA_VAULT_ITEMS__).toEqual(items);

    dispose();
    expect(listeners.get('message')?.size).toBe(0);
  });
});

/** Extrae una función de primer nivel del content script para probarla de verdad. */
function extractFunctionFrom(source: string, name: string): (...args: any[]) => any {
  const header = `function ${name}(`;
  const start = source.indexOf(header);
  if (start === -1) throw new Error(`No se encontró ${name}`);

  const open = source.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  if (end === -1) throw new Error(`No se encontró el cierre de ${name}`);

  const consts = ['NON_TEXT_INPUT_TYPES', 'USERNAME_INPUT_KEYWORDS']
    .map((constName) => {
      const at = source.indexOf(`const ${constName}`);
      if (at === -1) throw new Error(`No se encontró ${constName}`);
      return source.slice(at, source.indexOf(';', at) + 1);
    })
    .join('\n');

  // eslint-disable-next-line no-new-func
  return new Function(`${consts}\n${source.slice(start, end)}\n; return ${name};`)();
}

type FakeInput = Record<string, any>;

function fakeInput(props: FakeInput = {}): FakeInput {
  const { autocomplete, ...rest } = props as { autocomplete?: string } & FakeInput;
  return {
    tagName: 'INPUT',
    type: 'text',
    name: '',
    id: '',
    form: null,
    closest: () => null,
    getAttribute: (attr: string) => (attr === 'autocomplete' && autocomplete ? autocomplete : null),
    ...rest,
  };
}

const isAutofillCandidateInput = extractFunctionFrom(contentScriptSource, 'isAutofillCandidateInput');

describe('Selección de campos con icono de autocompletado (content script)', () => {
  it('acepta los campos típicos de un formulario de acceso', () => {
    expect(isAutofillCandidateInput(fakeInput({ type: 'password' }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ type: 'email' }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ autocomplete: 'username' }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ name: 'usuario' }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ id: 'login-username' }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ name: 'identifier' }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ name: 'Passwd', type: 'password' }))).toBe(true);
  });

  it('descarta buscadores y controles que nunca son credenciales', () => {
    expect(isAutofillCandidateInput(fakeInput({ name: 'q', id: 'search' }))).toBe(false);
    expect(isAutofillCandidateInput(fakeInput({ type: 'checkbox', name: 'user' }))).toBe(false);
    expect(isAutofillCandidateInput(fakeInput({ type: 'submit', name: 'login' }))).toBe(false);
    expect(isAutofillCandidateInput(fakeInput({ type: 'hidden', name: 'csrf' }))).toBe(false);
    expect(isAutofillCandidateInput(fakeInput({ tagName: 'TEXTAREA', name: 'user' }))).toBe(false);
  });

  it('solo acepta texto plano cuando el formulario también tiene contraseña', () => {
    const loginForm = { querySelector: (sel: string) => (sel.includes('password') ? {} : null) };
    const searchForm = { querySelector: () => null };

    expect(isAutofillCandidateInput(fakeInput({ form: searchForm }))).toBe(false);
    expect(isAutofillCandidateInput(fakeInput({ form: loginForm }))).toBe(true);
    expect(isAutofillCandidateInput(fakeInput({ closest: () => loginForm }))).toBe(true);
  });
});

describe('Contratos de la extensión (regresiones conocidas)', () => {
  it('el content script no vuelve a usar document.contains() sobre el Shadow DOM', () => {
    expect(contentScriptSource).not.toContain('document.contains(input._arcaIconAttached)');
    expect(contentScriptSource).toContain('existing.icon.isConnected && wrapper.contains(existing.icon)');
    expect(contentScriptSource).toContain('function pruneStaleIcons()');
  });

  it('el content script mantiene un único registro de iconos y listeners', () => {
    expect(contentScriptSource).toContain('const iconRegistry = new Map()');
    expect(contentScriptSource).toContain('iconRegistry.delete(input)');
    expect(contentScriptSource).toContain('window.addEventListener(\'resize\', scheduleRepositionAllIcons');
    expect(contentScriptSource.match(/input\.addEventListener\('focus'/g)).toHaveLength(1);
  });

  it('el popover ya no se cierra solo al hacer clic en el campo', () => {
    expect(contentScriptSource).toContain('clickedManagedInput');
    expect(contentScriptSource).toContain('function isInlineDropdownOpenFor(input)');
  });

  it('la sincronización solo se acepta desde la pestaña de la bóveda y su mismo origen', () => {
    expect(contentScriptSource).toContain('if (!isVaultAppPage()) return;\n  if (event.origin && event.origin !== window.location.origin) return;');
  });

  it('la extensión no usa reglas permisivas que enganchen cualquier formulario', () => {
    expect(contentScriptSource).not.toContain('input.form || input.closest(\'form\')');
  });
});

describe('Premisa Zero-Knowledge en el almacenamiento de la extensión', () => {
  it('la bóveda sincronizada nunca se escribe en chrome.storage.local', () => {
    expect(backgroundSource).not.toContain('chrome.storage.local.set({ arca_vault_items');
    expect(popupSource).not.toContain('chrome.storage.local.set({ arca_vault_items');
    expect(popupSource).not.toContain('chrome.storage.local.get(\'arca_vault_items\'');
    expect(contentScriptSource).not.toContain('chrome.storage.local.get(\'arca_vault_items\'');
  });

  it('usa storage.session (solo RAM) y lo habilita para los content scripts', () => {
    expect(backgroundSource).toContain('setAccessLevel');
    expect(backgroundSource).toContain('TRUSTED_AND_UNTRUSTED_CONTEXTS');
    expect(backgroundSource).toContain('chrome.storage.session');
    expect(contentScriptSource).toContain('chrome.storage.session');
    expect(popupSource).toContain('chrome.storage.session');
  });

  it('purga la bóveda al cerrar la pestaña que la originó', () => {
    expect(backgroundSource).toContain('const vaultTabIds = new Set()');
    expect(backgroundSource).toContain('vaultStorageArea().remove(\'arca_vault_items\')');
  });
});
