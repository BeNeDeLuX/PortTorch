import crypto, { KeyObject } from "crypto";
import net from "net";

// A minimal X.509 v3 certificate builder on Node's own crypto, written so
// node-forge could go. Node parses certificates (`crypto.X509Certificate`)
// and signs (`crypto.sign`) but has no API to *assemble* one, and that
// was the only thing node-forge was still doing here: the webserver's
// self-signed certificate on first boot, and the throwaway CAs and server
// certificates the tests build. Encoding DER is the small half of ASN.1 -
// there is nothing to parse, every length is known, and the output is
// checked by OpenSSL the moment Node loads it - so the few tag encoders
// below are the whole dependency.
//
// Deliberately covers only what this codebase issues: RSA keys,
// SHA-256 signatures, a subject of CN and optional O, and the four
// extensions a server or CA certificate needs. Anything else is a reason
// to extend this file, not to guess.

export interface CertificateName {
  commonName: string;
  organizationName?: string;
}

export interface CertificateOptions {
  subject: CertificateName;
  /** Defaults to the subject, which makes the certificate self-signed. */
  issuer?: CertificateName;
  publicKey: KeyObject;
  /** The issuer's private key; for a self-signed certificate, the subject's own. */
  signingKey: KeyObject;
  serialNumber?: number;
  notBefore: Date;
  notAfter: Date;
  /** Emits basicConstraints (critical) when set; `true` marks a CA. */
  basicConstraints?: boolean;
  keyUsage?: Array<"digitalSignature" | "keyEncipherment" | "keyCertSign" | "cRLSign">;
  /** Emits extendedKeyUsage with serverAuth when true. */
  serverAuth?: boolean;
  subjectAltNames?: { dns?: string[]; ip?: string[] };
}

const OID = {
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
  commonName: "2.5.4.3",
  organizationName: "2.5.4.10",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectAltName: "2.5.29.17",
  serverAuth: "1.3.6.1.5.5.7.3.1",
};

// --- DER primitives ------------------------------------------------------

function tlv(tag: number, content: Buffer): Buffer {
  let length: Buffer;
  if (content.length < 0x80) {
    length = Buffer.from([content.length]);
  } else {
    const bytes: number[] = [];
    for (let n = content.length; n > 0; n >>= 8) bytes.unshift(n & 0xff);
    length = Buffer.from([0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), length, content]);
}

const sequence = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]) => tlv(0x31, Buffer.concat(items));
const octetString = (b: Buffer) => tlv(0x04, b);
const utf8String = (s: string) => tlv(0x0c, Buffer.from(s, "utf8"));
const boolean = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const nullValue = () => tlv(0x05, Buffer.alloc(0));
// Explicit context-specific tag, constructed: [n] wraps its content.
const explicit = (n: number, content: Buffer) => tlv(0xa0 | n, content);

// INTEGER is two's complement big-endian with no redundant leading byte;
// a positive value whose top bit is set needs a 0x00 in front of it.
function integer(n: number): Buffer {
  if (!Number.isInteger(n) || n < 0) throw new Error("serial number must be a non-negative integer");
  const bytes: number[] = [];
  do {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  } while (n > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

// Unused-bits count first, then the bytes - every BIT STRING here is
// byte-aligned (a key or a signature), except keyUsage, built separately.
const bitString = (b: Buffer) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));

function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map(Number);
  const bytes: number[] = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    for (let rest = part >> 7; rest > 0; rest >>= 7) chunk.unshift(0x80 | (rest & 0x7f));
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

// RFC 5280: UTCTime up to 2049, GeneralizedTime from 2050 on.
function time(d: Date): Buffer {
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  const body =
    `${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}` +
    `${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  const year = d.getUTCFullYear();
  return year < 2050 ? tlv(0x17, Buffer.from(pad(year % 100) + body, "ascii")) : tlv(0x18, Buffer.from(pad(year, 4) + body, "ascii"));
}

// --- X.509 structures ----------------------------------------------------

function name(n: CertificateName): Buffer {
  const rdn = (type: string, value: string) => set(sequence(oid(type), utf8String(value)));
  const rdns = [rdn(OID.commonName, n.commonName)];
  if (n.organizationName) rdns.push(rdn(OID.organizationName, n.organizationName));
  return sequence(...rdns);
}

function extension(type: string, critical: boolean, value: Buffer): Buffer {
  return sequence(oid(type), ...(critical ? [boolean(true)] : []), octetString(value));
}

// keyUsage is a BIT STRING of named bits: bit 0 is the most significant
// bit of the first byte. Trailing zero bits are not encoded, so the
// unused-bits count depends on the highest bit set.
const KEY_USAGE_BIT = { digitalSignature: 0, keyEncipherment: 2, keyCertSign: 5, cRLSign: 6 } as const;

function keyUsageValue(usages: NonNullable<CertificateOptions["keyUsage"]>): Buffer {
  let bits = 0;
  let highest = 0;
  for (const u of usages) {
    const bit = KEY_USAGE_BIT[u];
    bits |= 0x80 >> bit;
    highest = Math.max(highest, bit);
  }
  return tlv(0x03, Buffer.from([7 - highest, bits]));
}

function ipBytes(ip: string): Buffer {
  if (net.isIPv4(ip)) return Buffer.from(ip.split(".").map(Number));
  if (net.isIPv6(ip)) {
    // Expand "::" to the eight groups it stands for.
    const [head, tail = ""] = ip.split("::");
    const h = head ? head.split(":") : [];
    const t = tail ? tail.split(":") : [];
    const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
    const out = Buffer.alloc(16);
    groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
    return out;
  }
  throw new Error(`not an IP address: ${ip}`);
}

function subjectAltNameValue(sans: NonNullable<CertificateOptions["subjectAltNames"]>): Buffer {
  // GeneralName uses implicit context tags: dNSName is [2], iPAddress [7].
  const names = [
    ...(sans.dns ?? []).map((d) => tlv(0x82, Buffer.from(d, "ascii"))),
    ...(sans.ip ?? []).map((ip) => tlv(0x87, ipBytes(ip))),
  ];
  return sequence(...names);
}

function pem(label: string, der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** Builds and signs an X.509 v3 certificate; returns it as PEM. */
export function createCertificate(opts: CertificateOptions): string {
  const extensions: Buffer[] = [];
  if (opts.basicConstraints !== undefined) {
    extensions.push(extension(OID.basicConstraints, true, sequence(...(opts.basicConstraints ? [boolean(true)] : []))));
  }
  if (opts.keyUsage && opts.keyUsage.length > 0) {
    extensions.push(extension(OID.keyUsage, true, keyUsageValue(opts.keyUsage)));
  }
  if (opts.serverAuth) {
    extensions.push(extension(OID.extKeyUsage, false, sequence(oid(OID.serverAuth))));
  }
  if (opts.subjectAltNames && ((opts.subjectAltNames.dns?.length ?? 0) > 0 || (opts.subjectAltNames.ip?.length ?? 0) > 0)) {
    extensions.push(extension(OID.subjectAltName, false, subjectAltNameValue(opts.subjectAltNames)));
  }

  const signatureAlgorithm = sequence(oid(OID.sha256WithRSAEncryption), nullValue());
  const tbs = sequence(
    explicit(0, integer(2)), // version v3
    integer(opts.serialNumber ?? 1),
    signatureAlgorithm,
    name(opts.issuer ?? opts.subject),
    sequence(time(opts.notBefore), time(opts.notAfter)),
    name(opts.subject),
    opts.publicKey.export({ type: "spki", format: "der" }),
    ...(extensions.length > 0 ? [explicit(3, sequence(...extensions))] : [])
  );
  const signature = crypto.sign("sha256", tbs, opts.signingKey);
  return pem("CERTIFICATE", sequence(tbs, signatureAlgorithm, bitString(signature)));
}

export function generateRsaKeyPair(modulusLength = 2048): { publicKey: KeyObject; privateKey: KeyObject } {
  return crypto.generateKeyPairSync("rsa", { modulusLength });
}

export function privateKeyToPem(key: KeyObject): string {
  return key.export({ type: "pkcs8", format: "pem" }) as string;
}

/**
 * A self-signed certificate for `commonName` plus the given alternative
 * names, with its own fresh key - the shape the webserver's first-boot
 * certificate and most test fixtures need.
 *
 * A self-signed server certificate carries no keyUsage. OpenSSL's
 * X509_check_issued (what `X509Certificate#checkIssued` and the Settings
 * page's "self-signed" flag run) refuses an issuer whose keyUsage lacks
 * keyCertSign - so a self-signed leaf declaring only digitalSignature and
 * keyEncipherment is reported as *not* issued by itself, while one with
 * no keyUsage at all is. TLS needs neither bit on a leaf. A CA gets
 * keyCertSign and cRLSign, which is what makes it an issuer.
 */
export function createSelfSignedCertificate(opts: {
  commonName: string;
  notBefore?: Date;
  notAfter: Date;
  dns?: string[];
  ip?: string[];
  basicConstraints?: boolean;
  serialNumber?: number;
}): { cert: string; key: string } {
  const keys = generateRsaKeyPair();
  const cert = createCertificate({
    subject: { commonName: opts.commonName },
    publicKey: keys.publicKey,
    signingKey: keys.privateKey,
    serialNumber: opts.serialNumber,
    notBefore: opts.notBefore ?? new Date(),
    notAfter: opts.notAfter,
    basicConstraints: opts.basicConstraints,
    keyUsage: opts.basicConstraints ? ["keyCertSign", "cRLSign"] : undefined,
    serverAuth: !opts.basicConstraints,
    subjectAltNames: opts.dns || opts.ip ? { dns: opts.dns, ip: opts.ip } : undefined,
  });
  return { cert, key: privateKeyToPem(keys.privateKey) };
}
