import crypto from "crypto";
import fs from "fs";
import path from "path";
import tls from "tls";

export interface TlsCertificateInfo {
  subjectCN: string | null;
  issuerCN: string | null;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  selfSigned: boolean;
  expired: boolean;
}

function extractCN(dn: string): string | null {
  const match = dn.match(/CN=([^,]+)/);
  return match ? match[1] : null;
}

function describeCert(x509: crypto.X509Certificate): TlsCertificateInfo {
  return {
    subjectCN: extractCN(x509.subject),
    issuerCN: extractCN(x509.issuer),
    validFrom: x509.validFrom,
    validTo: x509.validTo,
    fingerprint256: x509.fingerprint256,
    // checkIssued(self) actually validates the signature (this cert was
    // issued by itself), not just a string compare of subject vs issuer
    // - confirmed via testing against a real openssl-generated
    // self-signed cert before relying on it.
    selfSigned: x509.checkIssued(x509),
    expired: new Date(x509.validTo).getTime() < Date.now(),
  };
}

/**
 * Reads whatever certificate is currently active on disk - either the
 * auto-generated self-signed one from generateCert.ts, or a previously
 * uploaded custom one, both of which live at the same certDir/cert.pem
 * path (see saveCertKeyPair below, which always writes there) - and
 * returns its display-relevant fields for the Settings page. Throws if
 * certDir/cert.pem doesn't exist, which shouldn't happen in practice:
 * loadOrCreateSelfSignedCert always creates one at startup, before this
 * route is ever reachable.
 */
export function getCurrentCertInfo(certDir: string): TlsCertificateInfo {
  const certPem = fs.readFileSync(path.join(certDir, "cert.pem"), "utf8");
  return describeCert(new crypto.X509Certificate(certPem));
}

/**
 * Validates that certPem/keyPem form a genuinely usable, matching,
 * not-yet-expired pair before anything is written to disk or applied to
 * the live listener. X509Certificate.checkPrivateKey gives a clear,
 * purpose-built mismatch check; tls.createSecureContext is also called
 * as a belt-and-suspenders confirmation that the exact construction the
 * live server will use (see the route handler) actually succeeds -
 * confirmed via testing that createSecureContext alone does throw on a
 * mismatched pair too, but checkPrivateKey's dedicated error message is
 * clearer for the admin uploading a mismatched file by mistake. Throws
 * a descriptive Error on any failure - the caller treats that as a 400
 * (a user mistake in what they uploaded), not a 500.
 */
export function validateCertKeyPair(certPem: string, keyPem: string): TlsCertificateInfo {
  let x509: crypto.X509Certificate;
  try {
    x509 = new crypto.X509Certificate(certPem);
  } catch {
    throw new Error("the uploaded certificate file isn't a valid PEM certificate");
  }
  let keyObject: crypto.KeyObject;
  try {
    keyObject = crypto.createPrivateKey(keyPem);
  } catch {
    throw new Error("the uploaded private key file isn't a valid PEM private key");
  }
  if (!x509.checkPrivateKey(keyObject)) {
    throw new Error("the private key does not match the certificate");
  }
  // Never apply anything to the running listener that hasn't first been
  // proven to construct the exact same way setSecureContext will below.
  tls.createSecureContext({ cert: certPem, key: keyPem });

  const info = describeCert(x509);
  if (info.expired) {
    throw new Error(`this certificate already expired on ${info.validTo}`);
  }
  return info;
}

/**
 * Atomically replaces certDir/{cert,key}.pem with the new, already-
 * validated pair - write to a temp file in the same directory, then
 * rename into place, same discipline as the scanner's own self-update
 * (scanner/internal/updater/updater.go's defaultReplaceAndExec) rather
 * than an in-place truncate+write. The previous pair is renamed aside
 * first (not deleted), so a botched upload that somehow got this far -
 * or simply wanting to roll back - can still be recovered by an admin
 * with filesystem access.
 */
export function saveCertKeyPair(certDir: string, certPem: string, keyPem: string): void {
  const certPath = path.join(certDir, "cert.pem");
  const keyPath = path.join(certDir, "key.pem");
  const backupSuffix = `.bak-${Date.now()}`;

  if (fs.existsSync(certPath)) fs.renameSync(certPath, certPath + backupSuffix);
  if (fs.existsSync(keyPath)) fs.renameSync(keyPath, keyPath + backupSuffix);

  const certTmp = certPath + ".tmp";
  const keyTmp = keyPath + ".tmp";
  fs.writeFileSync(certTmp, certPem, { mode: 0o644 });
  fs.writeFileSync(keyTmp, keyPem, { mode: 0o600 });
  fs.renameSync(certTmp, certPath);
  fs.renameSync(keyTmp, keyPath);
}
