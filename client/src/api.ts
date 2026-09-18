// Cliente HTTP del frontend. Las cookies de sesion se gestionan por el navegador.

export interface SaltResponse {
  kdfSalt: string;
  kdfIterations: number;
}

export interface LoginResponse {
  wrappedVaultKey: string;
  wrapIv: string;
}

export interface VaultItemResponse {
  id: number | string;
  iv: string;
  ciphertext: string;
  createdAt?: string;
  updatedAt?: string;
}

// Permite cambiar el origen de la API en despliegues y usa el proxy de Vite por defecto.
const apiBase = import.meta.env.VITE_API_BASE_URL ?? '/api';

/** Ejecuta una petición JSON con cookies de sesión y convierte los errores HTTP en excepciones útiles. */
async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    let message = 'No se pudo completar la solicitud';
    try {
      const body = await response.json() as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // Conserva el mensaje generico si el servidor no devolvio JSON.
    }
    throw new Error(message);
  }

  // Algunos 201 no llevan cuerpo (registro), pero crear un item devuelve JSON con su id.
  if (response.status === 204 || !response.headers.get('content-type')) return undefined as T;
  return response.json() as Promise<T>;
}

/** Obtiene el salt y las iteraciones necesarias para derivar las claves de login. */
export function getAuthSalt(email: string) {
  return request<SaltResponse>(`/auth/salt?email=${encodeURIComponent(email)}`);
}

/** Envia al servidor solo material derivado y blobs cifrados preparados por el cliente. */
export function registerAccount(payload: {
  email: string;
  kdfSalt: string;
  kdfIterations: number;
  authHash: string;
  wrappedVaultKey: string;
  wrapIv: string;
}) {
  return request<void>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

/** Inicia sesion y devuelve la Vault Key envuelta para desenvolverla en memoria. */
export function loginAccount(payload: { email: string; authHash: string }) {
  return request<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

/** Solicita el borrado de la cookie de sesion del navegador. */
export function logoutAccount() {
  return request<void>('/auth/logout', { method: 'POST' });
}

/** Recupera los blobs cifrados de la cuenta activa; nunca devuelve texto plano. */
export function getVaultItems() {
  return request<VaultItemResponse[]>('/vault');
}

/** Persiste un item ya cifrado por el cliente y devuelve su identificador. */
export function createVaultItem(payload: { iv: string; ciphertext: string }) {
  return request<{ id: number | string }>('/vault', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

/** Reemplaza el blob cifrado de un item perteneciente a la cuenta activa. */
export function updateVaultItem(id: number | string, payload: { iv: string; ciphertext: string }) {
  return request<void>(`/vault/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

/** Elimina un item de la cuenta activa por su identificador. */
export function deleteVaultItem(id: number | string) {
  return request<void>(`/vault/${encodeURIComponent(id)}`, { method: 'DELETE' });
}