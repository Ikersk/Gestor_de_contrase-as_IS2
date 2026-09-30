// Puente entre la bóveda desbloqueada (en memoria) y la extensión Arca Shield.
//
// Premisa Zero-Knowledge: este módulo solo se activa mientras la bóveda está
// desbloqueada en la pestaña, nunca envía nada al servidor y borra la copia
// local de la extensión al cerrar sesión o al cerrar/recargar la pestaña.
// La extensión guarda esa copia en chrome.storage.session (solo RAM, nunca en disco).

export interface ExtensionVaultItem {
  id: number | string;
  title: string;
  username: string;
  password: string;
  urls: string[];
}

const SYNC_TYPE = "ARCA_VAULT_SYNC";
const CLEAR_TYPE = "ARCA_VAULT_CLEAR";
const REQUEST_TYPE = "ARCA_REQUEST_SYNC";

interface VaultGlobals {
  __ARCA_VAULT_ITEMS__?: ExtensionVaultItem[];
}

/** Normaliza una credencial descifrada al formato que consume la extensión. */
export function toExtensionItems(
  credentials: Array<ExtensionVaultItem>,
): ExtensionVaultItem[] {
  if (!Array.isArray(credentials)) return [];

  return credentials.map((item) => ({
    id: item.id,
    title: typeof item.title === "string" ? item.title : "",
    username: typeof item.username === "string" ? item.username : "",
    password: typeof item.password === "string" ? item.password : "",
    urls: Array.isArray(item.urls)
      ? item.urls
          .filter((url) => typeof url === "string" && url.trim() !== "")
          .map((url) => url.trim())
      : [],
  }));
}

/** Publica las credenciales desbloqueadas hacia la extensión instalada. */
export function publishVault(items: ExtensionVaultItem[]): void {
  if (!items || items.length === 0) {
    clearVault();
    return;
  }

  try {
    (window as unknown as VaultGlobals).__ARCA_VAULT_ITEMS__ = items;
  } catch {}

  try {
    window.postMessage({ type: SYNC_TYPE, credentials: items }, "*");
  } catch {}
}

/** Elimina la copia que la extensión mantenga de la bóveda. */
export function clearVault(): void {
  try {
    delete (window as unknown as VaultGlobals).__ARCA_VAULT_ITEMS__;
  } catch {}

  try {
    window.postMessage({ type: CLEAR_TYPE }, "*");
  } catch {}
}

/**
 * Atiende las peticiones de sincronización de la extensión (`ARCA_REQUEST_SYNC`),
 * por ejemplo cuando el service worker se reinicia o se reabre la bóveda.
 * Devuelve la función de limpieza para React.
 */
export function installExtensionBridge(
  readItems: () => ExtensionVaultItem[],
): () => void {
  const onMessage = (event: MessageEvent) => {
    if (event.origin && event.origin !== window.location.origin) return;
    if (!event.data || event.data.type !== REQUEST_TYPE) return;
    publishVault(readItems());
  };

  window.addEventListener("message", onMessage);
  return () => window.removeEventListener("message", onMessage);
}
