// Cliente HTTP del frontend. Las cookies de sesion se gestionan por el navegador.

export interface SaltResponse {
  kdfSalt: string;
  kdfIterations: number;
}

export interface LoginResponse {
  wrappedVaultKey: string;
  wrapIv: string;
}

const apiBase = import.meta.env.VITE_API_BASE_URL ?? '/api';

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

  if (response.status === 201 || response.status === 204) return undefined as T;
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