import fs from "fs";
import os from "os";
import path from "path";
import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { getCurrentCertInfo, saveCertKeyPair, validateCertKeyPair } from "./certUpload";

// Builds a real self-signed cert+key pair via node-forge - the same
// library generateCert.ts itself uses to build the auto-generated
// self-signed cert, so these tests exercise real PEM material rather
// than hand-typed fixture strings. notAfterDays lets a test build a
// deliberately-expired cert.
function buildSelfSignedPair(commonName: string, notAfterDays = 365): { cert: string; key: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + notAfterDays);
  const attrs = [{ name: "commonName", value: commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert: forge.pki.certificateToPem(cert), key: forge.pki.privateKeyToPem(keys.privateKey) };
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
