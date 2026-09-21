import { describe, expect, it } from "vitest";
import { auditVault } from "./vault-health";
import type { DecryptedCredential } from "./vault";
import type { VaultHealthAlert } from "./vault-health";

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

  it("includes breached alerts in the report and score", () => {
    const breachedAlerts: VaultHealthAlert[] = [
      {
        id: 3,
        title: "Acceso 3",
        username: "user3",
        reason: "Esta contraseña aparece 1,234 veces en filtraciones conocidas.",
      },
    ];

    const report = auditVault(
      [
        credential(1, "A7!qzP2#Lm9@rT4$"),
        credential(2, "A7!qzP2#Lm9@rT4$"),
        credential(3, "A7!qzP2#Lm9@rT4$"),
      ],
      breachedAlerts
    );

    expect(report.breached).toHaveLength(1);
    expect(report.breached[0].id).toBe(3);
    // credential 3 is breached, credentials 1 & 2 are reused = all 3 affected
    expect(report.score).toBe(0);
  });

  it("does not double-count breached credentials that are also weak or reused", () => {
    const breachedAlerts: VaultHealthAlert[] = [
      {
        id: 1,
        title: "GitHub",
        username: "user1",
        reason: "Aparece en filtraciones.",
      },
    ];

    const report = auditVault(
      [
        credential(1, "short", "GitHub"),
        credential(2, "A7!qzP2#Lm9@rT4$"),
      ],
      breachedAlerts
    );

    // credential 1 is weak + reused (only 1 so not reused) + breached = 1 affected
    // credential 2 is healthy = 0 affected
    expect(report.score).toBe(50);
  });
});