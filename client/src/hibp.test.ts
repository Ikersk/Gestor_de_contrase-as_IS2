import { describe, expect, it, vi, beforeEach } from "vitest";
import { sha1Hash, checkPasswordBreach, checkCredentialsBreach } from "./hibp";
import type { DecryptedCredential } from "./vault";

// Test vector: "password" -> SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const KNOWN_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

function credential(id: number, password: string, title = `Acceso ${id}`): DecryptedCredential {
  return { id, title, username: `user${id}`, password, urls: ["https://example.com"] };
}

describe("hibp", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("sha1Hash", () => {
    it("computes SHA-1 correctly for a known input", async () => {
      const hash = await sha1Hash("password");
      expect(hash).toBe(KNOWN_SHA1);
    });

    it("returns uppercase hex", async () => {
      const hash = await sha1Hash("test");
      expect(hash).toMatch(/^[0-9A-F]{40}$/);
    });
  });

  describe("checkPasswordBreach", () => {
    it("returns count when password is found in breach data", async () => {
      // "password" has SHA-1 starting with 5BAA6
      const mockLine = `${KNOWN_SHA1.slice(5)}:12345`;
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          text: () => Promise.resolve(mockLine),
        })
      );

      const count = await checkPasswordBreach("password");
      expect(count).toBe(12345);
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining("https://api.pwnedpasswords.com/range/5BAA6"),
        expect.objectContaining({
          headers: expect.objectContaining({
            "Add-Padding": "true",
          }),
        })
      );
    });

    it("returns 0 when password is not in breach data", async () => {
      const safeHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB";
      const mockLine = `${safeHash.slice(5)}:0`;
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          text: () => Promise.resolve(mockLine),
        })
      );

      const count = await checkPasswordBreach("safe-password-not-found");
      expect(count).toBe(0);
    });

    it("throws on API error", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: false,
          status: 429,
        })
      );

      await expect(checkPasswordBreach("test")).rejects.toThrow("HIBP API error: 429");
    });

    it("never sends the full hash or plaintext", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(""),
      });
      vi.stubGlobal("fetch", fetchFn);

      await checkPasswordBreach("password");

      const calledUrl = fetchFn.mock.calls[0][0];
      // URL should only contain the 5-char prefix, not the full hash
      expect(calledUrl).not.toContain("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
      // URL should contain only the prefix (5BAA6 for "password")
      expect(calledUrl).toContain("5BAA6");
      // URL should NOT contain the suffix
      expect(calledUrl).not.toContain("1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    });
  });

  describe("checkCredentialsBreach", () => {
    it("returns alerts for breached passwords", async () => {
      const mockLine = `${KNOWN_SHA1.slice(5)}:500`;
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          text: () => Promise.resolve(mockLine),
        })
      );

      const credentials = [
        credential(1, "password", "GitHub"),
        credential(2, "safe-password-not-in-list", "GitLab"),
      ];

      const alerts = await checkCredentialsBreach(credentials);
      expect(alerts).toHaveLength(1);
      expect(alerts[0].id).toBe(1);
      expect(alerts[0].title).toBe("GitHub");
      expect(alerts[0].reason).toContain("500");
    });

    it("returns empty array when no passwords are breached", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          text: () => Promise.resolve("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB:0"),
        })
      );

      const credentials = [credential(1, "safe-password")];
      const alerts = await checkCredentialsBreach(credentials);
      expect(alerts).toHaveLength(0);
    });

    it("reports progress correctly", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          text: () => Promise.resolve(""),
        })
      );

      const credentials = [credential(1, "a"), credential(2, "b"), credential(3, "c")];
      const progressCalls: Array<[number, number]> = [];
      await checkCredentialsBreach(credentials, (checked, total) => {
        progressCalls.push([checked, total]);
      });

      expect(progressCalls).toHaveLength(3);
      expect(progressCalls[2]).toEqual([3, 3]);
    });

    it("handles partial API failures gracefully", async () => {
      let callCount = 0;
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation(() => {
          callCount++;
          if (callCount === 1) {
            return Promise.resolve({
              ok: true,
              text: () => Promise.resolve(`${KNOWN_SHA1.slice(5)}:100`),
            });
          }
          // Second call fails
          return Promise.resolve({ ok: false, status: 500 });
        })
      );

      const credentials = [credential(1, "password"), credential(2, "another")];
      const alerts = await checkCredentialsBreach(credentials);
      // Should still get the first breached password
      expect(alerts).toHaveLength(1);
      expect(alerts[0].id).toBe(1);
    });
  });
});
