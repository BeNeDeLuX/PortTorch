import crypto from "crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildOtpauthUrl, generateRecoveryCodes, generateSecret, verifyToken } from "./totp";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Independent reference implementation of RFC 4226 HOTP, deliberately
// written differently from totp.ts's own (DataView instead of
// Buffer.writeUInt32BE, a bit-buffer loop instead of totp.ts's own
// bits-remaining loop for base32 decode) - the point of these tests is to
// catch a bug in the *shared logic* (byte packing, truncation offset,
// final modulo), which a copy-pasted "reference" would never expose.
function referenceBase32Decode(input: string): Buffer {
  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const char of input.toUpperCase()) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    buffer = (buffer << 5) | idx;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      bytes.push((buffer >> bitsLeft) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function referenceHotp(secret: Buffer, counter: number): string {
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter % 2 ** 32);
  const counterBuf = Buffer.from(view.buffer);

  const hmac = crypto.createHmac("sha1", secret).update(counterBuf).digest();
  const offset = hmac[19] & 0xf;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % 1_000_000).padStart(6, "0");
}

function referenceTotpAt(secret: string, unixMs: number): string {
  const counter = Math.floor(unixMs / 1000 / 30);
  return referenceHotp(referenceBase32Decode(secret), counter);
}

describe("generateSecret", () => {
  it("produces a base32 string with no padding/invalid characters", () => {
    expect(generateSecret()).toMatch(/^[A-Z2-7]+$/);
  });

  it("produces a different secret each time", () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });
});

describe("buildOtpauthUrl", () => {
  it("embeds the secret, username, and expected TOTP parameters", () => {
    const url = buildOtpauthUrl("ABCDEFGH", "alice");
    expect(url).toContain("otpauth://totp/");
    expect(url).toContain("secret=ABCDEFGH");
    expect(url).toContain("issuer=PortTorch");
    expect(url).toContain("algorithm=SHA1");
    expect(url).toContain("digits=6");
    expect(url).toContain("period=30");
    expect(url).toContain(encodeURIComponent("PortTorch:alice"));
  });
});

describe("verifyToken", () => {
  const secret = generateSecret();

  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("accepts a code matching an independently-implemented reference TOTP", () => {
    const now = new Date("2024-06-01T12:00:00.000Z");
    vi.setSystemTime(now);
    const code = referenceTotpAt(secret, now.getTime());
    expect(verifyToken(secret, code)).toBe(true);
  });

  it("rejects a code generated for a different secret", () => {
    const now = new Date("2024-06-01T12:00:00.000Z");
    vi.setSystemTime(now);
    const wrongSecret = generateSecret();
    const code = referenceTotpAt(wrongSecret, now.getTime());
    expect(verifyToken(secret, code)).toBe(false);
  });

  it("tolerates one time step of clock drift in either direction", () => {
    const now = new Date("2024-06-01T12:00:00.000Z");
    vi.setSystemTime(now);
    const oneStepEarlier = referenceTotpAt(secret, now.getTime() - 30_000);
    const oneStepLater = referenceTotpAt(secret, now.getTime() + 30_000);
    expect(verifyToken(secret, oneStepEarlier)).toBe(true);
    expect(verifyToken(secret, oneStepLater)).toBe(true);
  });

  it("rejects a code two time steps away", () => {
    const now = new Date("2024-06-01T12:00:00.000Z");
    vi.setSystemTime(now);
    const twoStepsEarlier = referenceTotpAt(secret, now.getTime() - 60_000);
    expect(verifyToken(secret, twoStepsEarlier)).toBe(false);
  });

  it("rejects malformed input", () => {
    expect(verifyToken(secret, "")).toBe(false);
    expect(verifyToken(secret, "12345")).toBe(false);
    expect(verifyToken(secret, "1234567")).toBe(false);
    expect(verifyToken(secret, "abcdef")).toBe(false);
  });
});

describe("generateRecoveryCodes", () => {
  it("generates 8 codes in the expected xxxxx-xxxxx format", () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(8);
    for (const code of codes) {
      expect(code).toMatch(/^[0-9a-f]{5}-[0-9a-f]{5}$/);
    }
  });

  it("generates unique codes", () => {
    const codes = generateRecoveryCodes();
    expect(new Set(codes).size).toBe(codes.length);
  });
});
