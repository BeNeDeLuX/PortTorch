import fs from "fs";
import os from "os";
import path from "path";
import { createSelfSignedCertificate } from "./x509";

export interface TlsMaterial {
  key: string;
  cert: string;
}

/**
 * Loads an existing self-signed certificate from certDir, or generates one
 * on first startup. This way, operation doesn't need an external CA.
 */
export function loadOrCreateSelfSignedCert(certDir: string): TlsMaterial {
  const keyPath = path.join(certDir, "key.pem");
  const certPath = path.join(certDir, "cert.pem");

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return {
      key: fs.readFileSync(keyPath, "utf8"),
      cert: fs.readFileSync(certPath, "utf8"),
    };
  }

  fs.mkdirSync(certDir, { recursive: true });

  const hostname = os.hostname();
  const notBefore = new Date();
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notBefore.getFullYear() + 5);

  const { cert, key } = createSelfSignedCertificate({
    commonName: hostname,
    notBefore,
    notAfter,
    basicConstraints: false,
    dns: [hostname, "localhost"],
    ip: ["127.0.0.1"],
  });

  fs.writeFileSync(keyPath, key, { mode: 0o600 });
  fs.writeFileSync(certPath, cert, { mode: 0o644 });

  return { key, cert };
}
