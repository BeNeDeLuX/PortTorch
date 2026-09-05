import { describe, expect, it } from "vitest";
import { FINDING_LIMIT, limitFindings } from "../../src/lib/findingLimit";

// The ceiling exists so a large fleet cannot ship and render an unbounded
// result set. What matters most is the honesty of the flag: a page that
// silently omits findings is worse than one that does not truncate at
// all, because it still gets trusted for something it can no longer do.
describe("finding limit", () => {
  it("passes a normal result through untouched and unflagged", () => {
    const rows = Array.from({ length: 42 }, (_, i) => ({ i }));
    const result = limitFindings(rows);
    expect(result.items).toHaveLength(42);
    expect(result.total).toBe(42);
    expect(result.truncated).toBe(false);
    expect(result.limit).toBe(FINDING_LIMIT);
  });

  it("is not truncated at exactly the limit - the boundary belongs to the untruncated side", () => {
    const rows = Array.from({ length: FINDING_LIMIT }, (_, i) => ({ i }));
    const result = limitFindings(rows);
    expect(result.items).toHaveLength(FINDING_LIMIT);
    expect(result.truncated).toBe(false);
  });

  it("truncates one past the limit, and reports the real total", () => {
    const rows = Array.from({ length: FINDING_LIMIT + 1 }, (_, i) => ({ i }));
    const result = limitFindings(rows);
    expect(result.items).toHaveLength(FINDING_LIMIT);
    // The total is the number that existed, not the number returned -
    // that difference is the whole point of the flag.
    expect(result.total).toBe(FINDING_LIMIT + 1);
    expect(result.truncated).toBe(true);
  });

  it("keeps the first rows, so the caller's own ordering decides what survives", () => {
    const rows = Array.from({ length: FINDING_LIMIT + 10 }, (_, i) => ({ i }));
    const result = limitFindings(rows);
    // Every route sorts before calling this - worst-first for CVEs,
    // soonest-expiring for certificates - so "the first N" means "the N
    // that matter most", not an arbitrary N.
    expect(result.items[0]).toEqual({ i: 0 });
    expect(result.items[result.items.length - 1]).toEqual({ i: FINDING_LIMIT - 1 });
  });

  it("handles an empty result", () => {
    const result = limitFindings([]);
    expect(result.items).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.truncated).toBe(false);
  });
});
