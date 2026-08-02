import crypto from "crypto";
import { describe, expect, it } from "vitest";
import { hashApiKey } from "./apiKeyAuth";

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
