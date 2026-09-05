import { beforeEach, describe, expect, it } from "vitest";
import { isLockedOut, recordFailure, recordSuccess } from "./rateLimiter";

// A fresh key per test rather than a reset hook - the module's state is
// deliberately process-local with no exported clear, and inventing one
// just for tests would be a worse trade than unique keys.
let n = 0;
function freshKey(): string {
  n += 1;
  return `test-key-${n}-${Date.now()}`;
}

describe("recordFailure", () => {
  it("reports the transition into a lockout exactly once", () => {
    const key = freshKey();
    // Four failures are not yet a lockout.
    for (let i = 0; i < 4; i++) {
      expect(recordFailure(key), `attempt ${i + 1}`).toBe(false);
      expect(isLockedOut(key)).toBe(false);
    }
    // The fifth is.
    expect(recordFailure(key)).toBe(true);
    expect(isLockedOut(key)).toBe(true);

    // And every attempt after it is not - this is the whole reason the
    // function returns anything. Alerting on each refused attempt would
    // mean one message per guess for the next fifteen minutes.
    for (let i = 0; i < 5; i++) {
      expect(recordFailure(key), `post-lockout attempt ${i + 1}`).toBe(false);
    }
  });

  it("forgets a key after a success, so a later lockout can alert again", () => {
    const key = freshKey();
    for (let i = 0; i < 5; i++) recordFailure(key);
    expect(isLockedOut(key)).toBe(true);

    recordSuccess(key);
    expect(isLockedOut(key)).toBe(false);

    for (let i = 0; i < 4; i++) expect(recordFailure(key)).toBe(false);
    expect(recordFailure(key)).toBe(true);
  });

  it("treats separate keys independently", () => {
    const a = freshKey();
    const b = freshKey();
    for (let i = 0; i < 5; i++) recordFailure(a);
    expect(isLockedOut(a)).toBe(true);
    // One account locking out must not lock out an unrelated one - the
    // login path records both an IP key and a username key.
    expect(isLockedOut(b)).toBe(false);
  });
});
