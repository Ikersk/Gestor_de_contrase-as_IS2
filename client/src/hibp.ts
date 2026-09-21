/**
 * Have I Been Pwned (HIBP) integration using k-Anonymity.
 *
 * Security model:
 * - Only the first 5 characters of the SHA-1 hash leave the browser.
 * - The full hash NEVER leaves the client.
 * - Plaintext passwords NEVER leave the client.
 * - The backend is never involved.
 */

import type { DecryptedCredential } from "./vault";
import type { VaultHealthAlert } from "./vault-health";

const HIBP_API_BASE = "https://api.pwnedpasswords.com/range";
const MAX_CONCURRENT = 6;
const REQUEST_DELAY_MS = 100;

/** Converts an ArrayBuffer to a hex string. */
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Computes SHA-1 hash of a password using Web Crypto API. */
export async function sha1Hash(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  return bufferToHex(hashBuffer);
}

/**
 * Checks if a password has been exposed in data breaches via HIBP k-Anonymity.
 *
 * 1. Compute SHA-1 of the password.
 * 2. Send only the first 5 characters (prefix) to HIBP API.
 * 3. Receive all suffixes that share that prefix.
 * 4. Compare locally in RAM to find if our suffix exists.
 *
 * @returns The number of times the password appeared in breaches, or 0 if safe.
 */
export async function checkPasswordBreach(password: string): Promise<number> {
  const hash = await sha1Hash(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetch(`${HIBP_API_BASE}/${prefix}`, {
    headers: {
      "Add-Padding": "true",
      "User-Agent": "Arca-Password-Manager",
    },
  });

  if (!response.ok) {
    throw new Error(`HIBP API error: ${response.status}`);
  }

  const text = await response.text();
  const lines = text.split("\n");

  for (const line of lines) {
    const [hashSuffix, count] = line.split(":");
    if (hashSuffix.trim() === suffix) {
      return parseInt(count.trim(), 10);
    }
  }

  return 0;
}

/**
 * Checks multiple credentials against HIBP with controlled concurrency.
 *
 * @param credentials - Decrypted credentials to check.
 * @param onProgress - Callback for progress updates (checked count, total).
 * @returns Array of alerts for breached passwords.
 */
export async function checkCredentialsBreach(
  credentials: DecryptedCredential[],
  onProgress?: (checked: number, total: number) => void
): Promise<VaultHealthAlert[]> {
  const breached: VaultHealthAlert[] = [];
  let checked = 0;
  const total = credentials.length;

  // Process in batches with controlled concurrency
  for (let i = 0; i < total; i += MAX_CONCURRENT) {
    const batch = credentials.slice(i, i + MAX_CONCURRENT);

    const results = await Promise.allSettled(
      batch.map(async (credential) => {
        const count = await checkPasswordBreach(credential.password);
        return { credential, count };
      })
    );

    for (const result of results) {
      checked++;
      if (result.status === "fulfilled" && result.value.count > 0) {
        breached.push({
          id: result.value.credential.id,
          title: result.value.credential.title,
          username: result.value.credential.username,
          reason: `Esta contraseña aparece ${result.value.count.toLocaleString()} veces en filtraciones conocidas.`,
        });
      }
      onProgress?.(checked, total);
    }

    // Delay between batches to respect rate limits
    if (i + MAX_CONCURRENT < total) {
      await new Promise((resolve) => setTimeout(resolve, REQUEST_DELAY_MS));
    }
  }

  return breached;
}
