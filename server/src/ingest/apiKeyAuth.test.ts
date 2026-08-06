import crypto from "crypto";
import { describe, expect, it } from "vitest";
import { hashApiKey, parseBearerToken } from "./apiKeyAuth";

describe("hashApiKey", () => {
  it("is deterministic", () => {
    expect(hashApiKey("some-api-key")).toBe(hashApiKey("some-api-key"));
  });

  it("is sensitive to every character (no truncation/normalization)", () => {
    expect(hashApiKey("some-api-key")).not.toBe(hashApiKey("some-api-keyX"));
  });

  it("matches a hand-computed SHA-256 hex digest", () => {
    const expected = crypto.createHash("sha256").update("some-api-key", "utf8").digest("hex");
    expect(hashApiKey("some-api-key")).toBe(expected);
  });

  it("produces a 64-character lowercase hex string", () => {
    expect(hashApiKey("anything")).toMatch(/^[0-9a-f]{64}$/);
  });
});

// Replaced a /^Bearer\s+(.+)$/i regex that was vulnerable to polynomial
// ReDoS on attacker-controlled header input (confirmed by timing it: ~730ms
// against a ~32KB crafted header, growing quadratically with input length,
// since \s+ and .+ overlap on whitespace characters). Matches the old
// regex's behavior except for one deliberate improvement: trailing
// whitespace after the token is now trimmed rather than folded into the
// token itself (the old (.+)$ greedily captured it), so an incidental
// trailing space/newline from a client no longer causes the hash lookup
// to mismatch.
describe("parseBearerToken", () => {
  it("extracts the token after a single space", () => {
    expect(parseBearerToken("Bearer abc123")).toBe("abc123");
  });

  it("is case-insensitive on the scheme", () => {
    expect(parseBearerToken("bearer abc123")).toBe("abc123");
    expect(parseBearerToken("BEARER abc123")).toBe("abc123");
  });

  it("collapses multiple/mixed whitespace between scheme and token", () => {
    expect(parseBearerToken("Bearer   abc123")).toBe("abc123");
    expect(parseBearerToken("Bearer\tabc123")).toBe("abc123");
  });

  it("trims trailing whitespace off the token", () => {
    expect(parseBearerToken("Bearer abc123  ")).toBe("abc123");
  });

  it("returns null with no scheme prefix", () => {
    expect(parseBearerToken("abc123")).toBeNull();
  });

  it("returns null with no whitespace between scheme and token", () => {
    expect(parseBearerToken("Bearerabc123")).toBeNull();
  });

  it("returns null for the scheme with nothing after it", () => {
    expect(parseBearerToken("Bearer")).toBeNull();
    expect(parseBearerToken("Bearer ")).toBeNull();
  });

  it("returns null for an empty header", () => {
    expect(parseBearerToken("")).toBeNull();
  });

  it("preserves internal whitespace within the token itself", () => {
    expect(parseBearerToken("Bearer abc 123")).toBe("abc 123");
  });
});
