import { describe, expect, it } from "vitest";
import {
  getTotpSnapshot,
  isValidTotpSecret,
  normalizeTotpSecret,
} from "./totp";

describe("local TOTP support", () => {
  it("normalizes Base32 secrets and extracts them from otpauth URIs", () => {
    const secret = "JBSW Y3DP EHPK 3PXP";
    const uri = `otpauth://totp/Arca:demo?secret=${secret.replaceAll(" ", "")}&issuer=Arca`;

    expect(normalizeTotpSecret(secret)).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeTotpSecret(uri)).toBe("JBSWY3DPEHPK3PXP");
    expect(isValidTotpSecret(secret)).toBe(true);
    expect(isValidTotpSecret(uri)).toBe(true);
    expect(isValidTotpSecret("not-a-totp-secret")).toBe(false);
  });

  it("generates the RFC 6238 reference code with six digits", () => {
    const snapshot = getTotpSnapshot("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59_000);

    expect(snapshot.code).toBe("287082");
    expect(snapshot.code).toHaveLength(6);
    expect(snapshot.remainingSeconds).toBe(1);
  });
});