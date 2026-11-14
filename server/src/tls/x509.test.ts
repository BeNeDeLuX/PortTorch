import crypto, { X509Certificate } from "crypto";
import https from "https";
import { describe, expect, it } from "vitest";
import { createCertificate, createSelfSignedCertificate, generateRsaKeyPair, privateKeyToPem } from "./x509";

// The encoder is checked by what OpenSSL makes of its output, not by
// comparing bytes: X509Certificate parses it, reports every field back,
// verifies the signature, and a real TLS handshake accepts it. A
// hand-rolled DER writer that passes all of that is correct in every way
// that matters here.

describe("createSelfSignedCertificate", () => {
  const notBefore = new Date("2026-03-01T12:00:00Z");
  const notAfter = new Date("2031-03-01T12:00:00Z");
  const { cert, key } = createSelfSignedCertificate({
    commonName: "web.internal",
    notBefore,
    notAfter,
    basicConstraints: false,
    dns: ["web.internal", "localhost"],
    ip: ["127.0.0.1", "::1"],
    serialNumber: 200,
  });
  const x509 = new X509Certificate(cert);

  it("parses as the certificate that was asked for", () => {
    expect(x509.subject).toBe("CN=web.internal");
    expect(x509.issuer).toBe("CN=web.internal");
    expect(x509.validFromDate.toISOString()).toBe(notBefore.toISOString());
    expect(x509.validToDate.toISOString()).toBe(notAfter.toISOString());
    expect(x509.serialNumber).toBe("C8");
    expect(x509.ca).toBe(false);
    expect(x509.subjectAltName).toBe("DNS:web.internal, DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1");
    expect(x509.keyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
  });

  it("is signed by its own key, and the key is the one returned", () => {
    expect(x509.verify(x509.publicKey)).toBe(true);
    // What the Settings page's "self-signed" flag runs; it refuses an
    // issuer whose keyUsage lacks keyCertSign, which is why a self-signed
    // leaf carries no keyUsage at all.
    expect(x509.checkIssued(x509)).toBe(true);
    expect(x509.checkPrivateKey(crypto.createPrivateKey(key))).toBe(true);
    expect(key.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
  });

  it("matches the names it carries and nothing else", () => {
    expect(x509.checkHost("localhost")).toBe("localhost");
    expect(x509.checkHost("web.internal")).toBe("web.internal");
    expect(x509.checkHost("other.internal")).toBeUndefined();
    expect(x509.checkIP("127.0.0.1")).toBe("127.0.0.1");
    expect(x509.checkIP("::1")).toBe("::1");
    expect(x509.checkIP("10.0.0.1")).toBeUndefined();
  });

  it("serves a TLS connection that a client trusting it accepts", async () => {
    const server = https.createServer({ cert, key }, (_req, res) => res.end("ok"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const body = await new Promise<string>((resolve, reject) => {
        https
          .get({ host: "127.0.0.1", port, path: "/", ca: cert, servername: "localhost" }, (res) => {
            let data = "";
            res.on("data", (c) => (data += c));
            res.on("end", () => resolve(data));
          })
          .on("error", reject);
      });
      expect(body).toBe("ok");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("createCertificate", () => {
  it("issues a CA and a leaf the CA signs, which chain for Node's verifier", () => {
    const caKeys = generateRsaKeyPair();
    const ca = new X509Certificate(
      createCertificate({
        subject: { commonName: "Test Root", organizationName: "Corp" },
        publicKey: caKeys.publicKey,
        signingKey: caKeys.privateKey,
        notBefore: new Date("2026-01-01T00:00:00Z"),
        notAfter: new Date("2036-01-01T00:00:00Z"),
        basicConstraints: true,
        keyUsage: ["keyCertSign", "cRLSign"],
      })
    );
    expect(ca.ca).toBe(true);
    expect(ca.subject).toBe("CN=Test Root\nO=Corp");

    const leafKeys = generateRsaKeyPair();
    const leaf = new X509Certificate(
      createCertificate({
        subject: { commonName: "leaf.internal" },
        issuer: { commonName: "Test Root", organizationName: "Corp" },
        publicKey: leafKeys.publicKey,
        signingKey: caKeys.privateKey,
        serialNumber: 2,
        notBefore: new Date("2026-01-01T00:00:00Z"),
        notAfter: new Date("2027-01-01T00:00:00Z"),
        basicConstraints: false,
        keyUsage: ["digitalSignature", "keyEncipherment"],
        serverAuth: true,
      })
    );
    expect(leaf.issuer).toBe(ca.subject);
    expect(leaf.checkIssued(ca)).toBe(true);
    expect(leaf.verify(ca.publicKey)).toBe(true);
    expect(leaf.verify(leafKeys.publicKey)).toBe(false);
    expect(leaf.checkPrivateKey(crypto.createPrivateKey(privateKeyToPem(leafKeys.privateKey)))).toBe(true);
  });

  it("writes dates after 2049 as GeneralizedTime and large serials without a sign bit", () => {
    const keys = generateRsaKeyPair();
    const x509 = new X509Certificate(
      createCertificate({
        subject: { commonName: "far" },
        publicKey: keys.publicKey,
        signingKey: keys.privateKey,
        serialNumber: 0x80,
        notBefore: new Date("2049-12-31T23:59:59Z"),
        notAfter: new Date("2050-01-01T00:00:00Z"),
      })
    );
    expect(x509.validFromDate.toISOString()).toBe("2049-12-31T23:59:59.000Z");
    expect(x509.validToDate.toISOString()).toBe("2050-01-01T00:00:00.000Z");
    expect(x509.serialNumber).toBe("80");
  });
});
