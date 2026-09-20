import { describe, expect, it } from "vitest";
import { auditVault } from "./vault-health";
import type { DecryptedCredential } from "./vault";

function credential(id: number, password: string, title = `Acceso ${id}`): DecryptedCredential {
  return { id, title, username: `user${id}`, password, urls: ["https://example.com"] };
}

describe("vault health audit", () => {
  it("finds every credential that reuses a password", () => {
    const report = auditVault([
      credential(1, "same-password", "GitHub"),
      credential(2, "same-password", "GitLab"),
      credential(3, "unique-password")
    ]);

    expect(report.reused.map((alert) => alert.id)).toEqual([1, 2]);
    expect(report.reused[0].title).toBe("GitHub");
  });

  it("marks short and low-diversity passwords as weak", () => {
    const report = auditVault([
      credential(1, "short"),
      credential(2, "aaaaaaaaaaaaaaaaaaaa"),
      credential(3, "A7!qzP2#Lm9@rT4$")
    ]);

    expect(report.weak.map((alert) => alert.id)).toEqual([1, 2]);
  });

  it("returns a perfect score for an empty or fully healthy vault", () => {
    expect(auditVault([]).score).toBe(100);
    expect(auditVault([credential(1, "A7!qzP2#Lm9@rT4$")]).score).toBe(100);
  });

  it("scores affected records once even when they match multiple alerts", () => {
    const report = auditVault([
      credential(1, "short"),
      credential(2, "short"),
      credential(3, "A7!qzP2#Lm9@rT4$")
    ]);

    expect(report.reused).toHaveLength(2);
    expect(report.weak).toHaveLength(2);
    expect(report.score).toBe(33);
  });
});