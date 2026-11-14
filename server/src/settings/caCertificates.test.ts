import { describe, expect, it } from "vitest";
import { createCertificate, generateRsaKeyPair } from "../tls/x509";
import { CaCertificateError, parseCaCertificate } from "./caCertificates";

// Real certificates built with the same builder generateCert.ts uses -
// a hand-written PEM constant would only prove that a fixed string parses.
function makeCert({ isCa }: { isCa: boolean }): string {
  const keys = generateRsaKeyPair();
  return createCertificate({
    subject: { commonName: isCa ? "Corp Root CA" : "mail.internal", organizationName: "Corp" },
    publicKey: keys.publicKey,
    signingKey: keys.privateKey,
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2028-01-01T00:00:00Z"),
    basicConstraints: isCa,
  });
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
    const lf = makeCert({ isCa: true });
    const a = parseCaCertificate(lf);
    const b = parseCaCertificate(`\n  ${lf.replace(/\n/g, "\r\n")}  \n`);
    expect(b.fingerprintSha256).toBe(a.fingerprintSha256);
    expect(b.pem).toBe(a.pem);
  });
});
