import { afterEach, describe, expect, it } from "vitest";
import { checkApiTokenRateLimit, resetApiTokenRateLimits } from "./rateLimit";
import { config } from "../config";

const original = config.apiTokenRateLimitPerMinute;

afterEach(() => {
  config.apiTokenRateLimitPerMinute = original;
  resetApiTokenRateLimits();
});

describe("checkApiTokenRateLimit", () => {
  it("allows up to the limit and blocks the request after it", () => {
    config.apiTokenRateLimitPerMinute = 3;
    const results = [1, 2, 3, 4].map(() => checkApiTokenRateLimit("token-a"));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    // The last allowed request reports zero budget left, and the blocked
    // one doesn't go negative.
    expect(results[2].remaining).toBe(0);
    expect(results[3].remaining).toBe(0);
  });

  // The token is the identity, so one noisy integration must not throttle
  // an unrelated one.
  it("counts each token separately", () => {
    config.apiTokenRateLimitPerMinute = 2;
    checkApiTokenRateLimit("token-a");
    checkApiTokenRateLimit("token-a");
    expect(checkApiTokenRateLimit("token-a").allowed).toBe(false);
    expect(checkApiTokenRateLimit("token-b").allowed).toBe(true);
  });

  it("starts a fresh window once the minute has elapsed", () => {
    config.apiTokenRateLimitPerMinute = 1;
    const t0 = 1_000_000;
    expect(checkApiTokenRateLimit("token-c", t0).allowed).toBe(true);
    expect(checkApiTokenRateLimit("token-c", t0 + 59_000).allowed).toBe(false);
    expect(checkApiTokenRateLimit("token-c", t0 + 60_000).allowed).toBe(true);
  });

  it("reports a reset time inside the current window, not a rolling one", () => {
    config.apiTokenRateLimitPerMinute = 5;
    const t0 = 2_000_000;
    const first = checkApiTokenRateLimit("token-d", t0);
    const later = checkApiTokenRateLimit("token-d", t0 + 30_000);
    // Both belong to the same window, so both report the same rollover -
    // a client that backs off until then is correct either way.
    expect(later.resetAt).toBe(first.resetAt);
  });

  // The escape hatch for a deployment whose own automation legitimately
  // exceeds any default: it must be a true bypass, not a very high limit.
  it("is disabled entirely at 0", () => {
    config.apiTokenRateLimitPerMinute = 0;
    for (let i = 0; i < 1000; i++) {
      expect(checkApiTokenRateLimit("token-e").allowed).toBe(true);
    }
    expect(checkApiTokenRateLimit("token-e").limit).toBe(0);
  });
});
