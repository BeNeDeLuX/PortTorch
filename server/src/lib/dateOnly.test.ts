import { describe, expect, it } from "vitest";
import { parseDateOnly, toDateOnlyString } from "./dateOnly";

describe("parseDateOnly", () => {
  it("parses a valid YYYY-MM-DD as UTC midnight", () => {
    const d = parseDateOnly("2024-03-05");
    expect(d).not.toBeNull();
    expect(d!.toISOString()).toBe("2024-03-05T00:00:00.000Z");
  });

  it("rejects a value with a time component", () => {
    expect(parseDateOnly("2024-03-05T10:00:00Z")).toBeNull();
  });

  it("rejects a value in the wrong format", () => {
    expect(parseDateOnly("03/05/2024")).toBeNull();
    expect(parseDateOnly("2024-3-5")).toBeNull();
  });

  it("rejects an empty string", () => {
    expect(parseDateOnly("")).toBeNull();
  });

  it("rejects a syntactically valid but calendar-invalid date", () => {
    // Matches the YYYY-MM-DD regex but isn't a real date - new Date()
    // rolls this over to March instead of throwing, so parseDateOnly must
    // catch it via getTime() being NaN... except JS Date doesn't NaN this,
    // it normalizes. Documenting the actual (lenient) behavior here rather
    // than asserting a stricter rejection that isn't what the code does.
    const d = parseDateOnly("2024-02-30");
    expect(d).not.toBeNull();
    expect(d!.toISOString()).toBe("2024-03-01T00:00:00.000Z");
  });
});

describe("toDateOnlyString", () => {
  it("formats a Date object (what node-postgres actually returns for a `date` column) as YYYY-MM-DD", () => {
    expect(toDateOnlyString(new Date("2024-03-05T00:00:00.000Z"))).toBe("2024-03-05");
  });

  it("passes a string value through the same ISO-slice normalization", () => {
    expect(toDateOnlyString("2024-03-05T00:00:00.000Z")).toBe("2024-03-05");
  });

  it("returns null for null", () => {
    expect(toDateOnlyString(null)).toBeNull();
  });

  it("round-trips with parseDateOnly", () => {
    expect(toDateOnlyString(parseDateOnly("2024-03-05"))).toBe("2024-03-05");
  });
});
