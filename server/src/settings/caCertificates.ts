import { X509Certificate } from "crypto";
import tls from "tls";
import { db } from "../db";

export interface ParsedCaCertificate {
  pem: string;
  subject: string;
  issuer: string;
  notBefore: Date;
  notAfter: Date;
  fingerprintSha256: string;
}

export class CaCertificateError extends Error {}

// Normalised so the same certificate uploaded with different line
// endings, or with the surrounding whitespace a copy-paste picks up,
// stores identically and is caught as a duplicate.
//
// Strips every carriage return rather than only the CRLF pairs: Windows
// tooling and several CAs emit PEM with CRLF, so text that has been
// through one conversion can carry a stray lone \r that a pair-wise
// replace leaves behind - and the stored PEM then differs from the same
// certificate pasted plainly.
function normalisePem(pem: string): string {
  return pem.replace(/\r/g, "").trim() + "\n";
}

// Node renders a distinguished name one attribute per line (`CN=x\nO=y`);
// the list shows it on one.
const oneLine = (dn: string) => dn.split("\n").join(", ");

export function parseCaCertificate(input: string): ParsedCaCertificate {
  const pem = normalisePem(input);
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch (err) {
    throw new CaCertificateError(`not a PEM certificate: ${err instanceof Error ? err.message : String(err)}`);
  }

  // A leaf certificate uploaded here would be accepted by Node as a trust
  // anchor for itself and nothing else - which looks like it worked until
  // the server rotates its certificate. Rejecting it now, with a reason,
  // beats an admin discovering it months later. `ca` is OpenSSL's reading
  // of basicConstraints, false when the extension is absent.
  if (!cert.ca) {
    throw new CaCertificateError(
      "this is not a CA certificate (basicConstraints CA:TRUE is missing) - upload the CA that signed the server's certificate, not the server's own certificate"
    );
  }

  return {
    pem,
    subject: oneLine(cert.subject),
    issuer: oneLine(cert.issuer),
    notBefore: cert.validFromDate,
    notAfter: cert.validToDate,
    // Node formats it as colon-separated uppercase hex; stored bare and
    // lower-case, the form every other fingerprint in this database uses.
    fingerprintSha256: cert.fingerprint256.replace(/:/g, "").toLowerCase(),
  };
}

// Cached for the process lifetime and invalidated on every change, the
// same shape as the SMTP transporter cache - these are read on every
// outbound TLS connection and change perhaps twice a year.
let cachedBundle: string[] | undefined;

export function resetCaBundle(): void {
  cachedBundle = undefined;
}

// The CA list to hand to Node as `ca`.
//
// **The public roots are included deliberately.** Passing `ca` *replaces*
// Node's default trust store rather than adding to it, so an admin who
// uploads their internal CA to reach their own mail relay would otherwise
// silently lose the ability to verify every public certificate - the
// GitHub release sync and any public webhook target among them. That
// failure would show up somewhere entirely unrelated to this page.
//
// Returns undefined when nothing is uploaded, so Node uses its own
// default rather than being handed a copy of it.
export async function caBundle(): Promise<string[] | undefined> {
  if (cachedBundle === undefined) {
    const rows = await db.selectFrom("trusted_ca_certificates").select(["pem"]).execute();
    cachedBundle = rows.length > 0 ? [...tls.rootCertificates, ...rows.map((r) => r.pem)] : [];
  }
  return cachedBundle.length > 0 ? cachedBundle : undefined;
}
