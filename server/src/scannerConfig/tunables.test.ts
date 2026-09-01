import { describe, expect, it } from "vitest";
import { SCANNER_TUNABLES, validateOverrides } from "./tunables";

describe("scanner config overrides", () => {
  it("accepts allowlisted keys within their bounds", () => {
    const result = validateOverrides({ masscanRate: 500, concurrency: 8 });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toEqual({ masscanRate: 500, concurrency: 8 });
  });

  it("rejects a key that isn't configurable, rather than dropping it", () => {
    // The exclusions that matter: setting these from here could orphan
    // the scanner or break scanning with no way to fix it remotely.
    for (const key of ["webserverUrl", "apiKey", "masscanPath", "insecureSkipVerify", "controlApiToken"]) {
      const result = validateOverrides({ [key]: 1 });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.errors[0]).toMatchObject({ key, message: "not a configurable setting" });
    }
  });

  it("rejects a misspelled key instead of silently ignoring it", () => {
    // Dropping it would render as a successful save that did nothing.
    const result = validateOverrides({ masscanrate: 500 });
    expect(result.ok).toBe(false);
  });

  it("enforces each tunable's own bounds", () => {
    expect(validateOverrides({ concurrency: 0 }).ok).toBe(false);
    expect(validateOverrides({ concurrency: 65 }).ok).toBe(false);
    expect(validateOverrides({ concurrency: 64 }).ok).toBe(true);
    // masscanRetries is the one tunable whose floor is legitimately 0.
    expect(validateOverrides({ masscanRetries: 0 }).ok).toBe(true);
  });

  it("rejects non-integers", () => {
    expect(validateOverrides({ concurrency: 2.5 }).ok).toBe(false);
    expect(validateOverrides({ concurrency: "8" as unknown as number }).ok).toBe(false);
  });

  it("accepts an empty object as 'no overrides'", () => {
    const result = validateOverrides({});
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toEqual({});
  });

  it("gives every tunable a sane, self-consistent definition", () => {
    for (const t of SCANNER_TUNABLES) {
      expect(t.min).toBeLessThan(t.max);
      expect(t.label.length).toBeGreaterThan(0);
      expect(t.help.length).toBeGreaterThan(0);
    }
  });

  it("carries a shipped default that its own bounds would accept", () => {
    // The defaults are a hand-kept copy of the scanner's own defaults()
    // (scanner/internal/config/config.go), and they are shown to admins
    // as "Default N" in the Configure dialog. A value outside the field's
    // own min/max would be a number the form refuses to accept while
    // claiming it is what a fresh install runs - the exact shape a typo
    // here would take.
    for (const t of SCANNER_TUNABLES) {
      expect(Number.isInteger(t.defaultValue)).toBe(true);
      expect(t.defaultValue).toBeGreaterThanOrEqual(t.min);
      expect(t.defaultValue).toBeLessThanOrEqual(t.max);
      // Round-tripping through the real validator proves the displayed
      // default is something an admin could actually save.
      expect(validateOverrides({ [t.key]: t.defaultValue }).ok).toBe(true);
    }
  });
});
