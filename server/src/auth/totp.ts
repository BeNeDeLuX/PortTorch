import crypto from "crypto";

// RFC 6238 (TOTP) on top of RFC 4226 (HOTP) - implemented directly against
// Node's own crypto rather than pulling in a TOTP library: the algorithm
// itself is small and this keeps the one genuinely security-critical piece
// of 2FA auditable in our own code, matching this codebase's existing
// preference for stdlib-only crypto (see the TLS certificate probe).
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;
// +/-1 step tolerates the caller's clock being up to ~30s off from ours in
// either direction, without widening the brute-force window too much.
const WINDOW = 1;

function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(secret: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  // A 64-bit big-endian counter - counter is a 30s step count, which stays
  // well within JS's safe integer range (and the 32-bit high half below)
  // for longer than this project will exist.
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 10 ** DIGITS).padStart(DIGITS, "0");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function generateSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

export function buildOtpauthUrl(secret: string, username: string): string {
  const label = encodeURIComponent(`PortTorch:${username}`);
  const issuer = encodeURIComponent("PortTorch");
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

export function verifyToken(base32Secret: string, token: string): boolean {
  const cleaned = token.trim();
  if (!/^\d{6}$/.test(cleaned)) return false;
  const secret = base32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (let drift = -WINDOW; drift <= WINDOW; drift++) {
    if (timingSafeEqualStr(hotp(secret, counter + drift), cleaned)) {
      return true;
    }
  }
  return false;
}

const RECOVERY_CODE_COUNT = 8;

// One-time backup codes for when the authenticator device itself is
// unavailable - shown to the user exactly once (like an API key), only
// their SHA-256 hash is ever stored (see hashApiKey's own reasoning: these
// are high-entropy generated values, not user-chosen passwords).
export function generateRecoveryCodes(): string[] {
  return Array.from({ length: RECOVERY_CODE_COUNT }, () => {
    const raw = crypto.randomBytes(5).toString("hex");
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}
