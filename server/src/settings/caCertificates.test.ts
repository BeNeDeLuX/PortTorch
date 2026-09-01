import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { CaCertificateError, parseCaCertificate } from "./caCertificates";

// Real certificates built with node-forge, the same approach
// tls/certUpload.test.ts already uses - a hand-written PEM constant would
// only prove that a fixed string parses.
function makeCert({ isCa }: { isCa: boolean }): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date("2026-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2028-01-01T00:00:00Z");
  const attrs = [{ name: "commonName", value: isCa ? "Corp Root CA" : "mail.internal" }, { name: "organizationName", value: "Corp" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{ name: "basicConstraints", cA: isCa }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

describe("parseCaCertificate", () => {
  it("accepts a CA certificate and pulls out what the list needs to show", () => {
    const parsed = parseCaCertificate(makeCert({ isCa: true }));
    expect(parsed.subject).toContain("CN=Corp Root CA");
    expect(parsed.issuer).toContain("CN=Corp Root CA");
    expect(parsed.notAfter.toISOString()).toBe("2028-01-01T00:00:00.000Z");
    expect(parsed.fingerprintSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a server certificate with a reason that says what to upload instead", () => {
    // Node would accept a leaf as a trust anchor for itself and nothing
    // else - which looks like it worked until the server rotates its
    // certificate, months later and somewhere else entirely.
    expect(() => parseCaCertificate(makeCert({ isCa: false }))).toThrow(CaCertificateError);
    try {
      parseCaCertificate(makeCert({ isCa: false }));
    } catch (err) {
      expect(String((err as Error).message)).toContain("not a CA certificate");
    }
  });

  it("rejects input that isn't a certificate at all", () => {
    expect(() => parseCaCertificate("hello")).toThrow(CaCertificateError);
    expect(() => parseCaCertificate("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")).toThrow(
      CaCertificateError
    );
  });

  it("fingerprints the certificate, not its formatting", () => {
    // A copy-paste that picks up CRLFs or stray whitespace is the same
    // certificate and has to be caught as a duplicate, not stored twice.
    // node-forge already emits CRLF, so this starts from a plain-LF copy
    // and re-adds them - otherwise the test would be converting twice and
    // proving something else.
    const pem = makeCert({ isCa: true });
    const lf = pem.replace(/\r/g, "");
    const a = parseCaCertificate(lf);
    const b = parseCaCertificate(`\n  ${lf.replace(/\n/g, "\r\n")}  \n`);
    expect(b.fingerprintSha256).toBe(a.fingerprintSha256);
    expect(b.pem).toBe(a.pem);
  });
});
