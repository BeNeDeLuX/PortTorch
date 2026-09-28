import { describe, expect, it } from "vitest";
import { MAX_SCAN_TAGS, normalizeScanTags, scanTagsSchema } from "./scanTags";

describe("scanTagsSchema", () => {
  it("accepts an omitted field and a real tag list", () => {
    expect(scanTagsSchema.parse(undefined)).toBeUndefined();
    expect(scanTagsSchema.parse(["Q3-Audit", "external-range"])).toEqual(["Q3-Audit", "external-range"]);
  });

  it("trims whitespace and rejects an empty or over-long tag", () => {
    expect(scanTagsSchema.parse(["  spaced  "])).toEqual(["spaced"]);
    expect(() => scanTagsSchema.parse([""])).toThrow();
    expect(() => scanTagsSchema.parse(["   "])).toThrow();
    expect(() => scanTagsSchema.parse(["x".repeat(65)])).toThrow();
  });

  it("rejects more than the cap", () => {
    const tooMany = Array.from({ length: MAX_SCAN_TAGS + 1 }, (_, i) => `tag-${i}`);
    expect(() => scanTagsSchema.parse(tooMany)).toThrow();
  });
});

describe("normalizeScanTags", () => {
  it("collapses undefined and an empty array to null", () => {
    expect(normalizeScanTags(undefined)).toBeNull();
    expect(normalizeScanTags([])).toBeNull();
  });

  // NULL is what "no tags requested" has always meant on these columns -
  // a caller explicitly sending an empty list should mean the same thing,
  // not a third state nothing downstream distinguishes anyway.
  it("dedupes case-sensitively, keeping the first spelling", () => {
    expect(normalizeScanTags(["q1-audit", "Q1-Audit", "q1-audit"])).toEqual(["q1-audit", "Q1-Audit"]);
  });

  it("passes an already-clean list through unchanged", () => {
    expect(normalizeScanTags(["a", "b", "c"])).toEqual(["a", "b", "c"]);
  });
});
