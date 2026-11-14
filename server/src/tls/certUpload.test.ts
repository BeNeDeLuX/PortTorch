import fs from "fs";
import os from "os";
import path from "path";
import { describe, expect, it } from "vitest";
import { getCurrentCertInfo, saveCertKeyPair, validateCertKeyPair } from "./certUpload";
import { createSelfSignedCertificate } from "./x509";

// Builds a real self-signed cert+key pair with the same builder
// generateCert.ts uses for the auto-generated self-signed cert, so these
// tests exercise real PEM material rather than hand-typed fixture
// strings. notAfterDays lets a test build a deliberately-expired cert.
function buildSelfSignedPair(commonName: string, notAfterDays = 365): { cert: string; key: string } {
  const notBefore = new Date();
  const notAfter = new Date(notBefore);
  notAfter.setDate(notBefore.getDate() + notAfterDays);
  return createSelfSignedCertificate({ commonName, notBefore, notAfter });
}

describe("validateCertKeyPair", () => {
  it("accepts a genuinely matching pair and reports its fields", () => {
    const { cert, key } = buildSelfSignedPair("matching-host");
    const info = validateCertKeyPair(cert, key);
    expect(info.subjectCN).toBe("matching-host");
    expect(info.issuerCN).toBe("matching-host");
    expect(info.selfSigned).toBe(true);
    expect(info.expired).toBe(false);
    expect(info.fingerprint256).toMatch(/^[0-9A-F:]+$/);
  });

  it("rejects a certificate paired with an unrelated private key", () => {
    const a = buildSelfSignedPair("host-a");
    const b = buildSelfSignedPair("host-b");
    expect(() => validateCertKeyPair(a.cert, b.key)).toThrow(/does not match/);
  });

  it("rejects a malformed certificate", () => {
    const { key } = buildSelfSignedPair("host-a");
    expect(() => validateCertKeyPair("not a real certificate", key)).toThrow(/isn't a valid PEM certificate/);
  });

  it("rejects a malformed private key", () => {
    const { cert } = buildSelfSignedPair("host-a");
    expect(() => validateCertKeyPair(cert, "not a real key")).toThrow(/isn't a valid PEM private key/);
  });

  it("rejects an already-expired certificate", () => {
    const { cert, key } = buildSelfSignedPair("host-expired", -1);
    expect(() => validateCertKeyPair(cert, key)).toThrow(/already expired/);
  });
});

describe("saveCertKeyPair / getCurrentCertInfo", () => {
  it("writes a pair to disk, reads it back, and backs up the previous one on overwrite", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "porttorch-cert-test-"));
    try {
      const first = buildSelfSignedPair("first-host");
      saveCertKeyPair(dir, first.cert, first.key);
      expect(getCurrentCertInfo(dir).subjectCN).toBe("first-host");

      const second = buildSelfSignedPair("second-host");
      saveCertKeyPair(dir, second.cert, second.key);
      expect(getCurrentCertInfo(dir).subjectCN).toBe("second-host");

      const backups = fs.readdirSync(dir).filter((f) => f.includes(".bak-"));
      expect(backups.some((f) => f.startsWith("cert.pem.bak-"))).toBe(true);
      expect(backups.some((f) => f.startsWith("key.pem.bak-"))).toBe(true);

      // No leftover .tmp files from the atomic write.
      expect(fs.readdirSync(dir).some((f) => f.endsWith(".tmp"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
