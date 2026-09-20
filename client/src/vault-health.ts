import type { DecryptedCredential } from "./vault";

export const MIN_HEALTHY_PASSWORD_LENGTH = 10;
export const MIN_HEALTHY_PASSWORD_ENTROPY = 50;

export interface VaultHealthAlert {
  id: number | string;
  title: string;
  username: string;
  reason: string;
}

export interface VaultHealthReport {
  score: number;
  reused: VaultHealthAlert[];
  weak: VaultHealthAlert[];
}

function estimateEntropy(password: string) {
  const alphabetSize = new Set(password).size;
  return password.length * Math.log2(alphabetSize || 1);
}

function toAlert(credential: DecryptedCredential, reason: string): VaultHealthAlert {
  return {
    id: credential.id,
    title: credential.title,
    username: credential.username,
    reason,
  };
}

export function auditVault(credentials: DecryptedCredential[]): VaultHealthReport {
  const passwordOwners = new Map<string, DecryptedCredential[]>();

  for (const credential of credentials) {
    const owners = passwordOwners.get(credential.password) ?? [];
    owners.push(credential);
    passwordOwners.set(credential.password, owners);
  }

  const reused = credentials
    .filter((credential) => (passwordOwners.get(credential.password)?.length ?? 0) > 1)
    .map((credential) => toAlert(credential, "Esta contraseña también se usa en otro acceso."));

  const weak = credentials
    .filter((credential) => {
      const entropy = estimateEntropy(credential.password);
      return credential.password.length < MIN_HEALTHY_PASSWORD_LENGTH
        || entropy < MIN_HEALTHY_PASSWORD_ENTROPY;
    })
    .map((credential) => toAlert(credential, "Usa una contraseña más larga y variada."));

  const affectedIds = new Set([...reused, ...weak].map((alert) => alert.id));
  const score = credentials.length === 0
    ? 100
    : Math.round(((credentials.length - affectedIds.size) / credentials.length) * 100);

  return { score, reused, weak };
}