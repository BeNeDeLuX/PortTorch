import { describe, expect, it } from "vitest";
import { parseTagList } from "./scanTags";

describe("parseTagList", () => {
  it("splits on commas and trims whitespace", () => {
    expect(parseTagList("Q3-Audit, external-range ,  pci")).toEqual(["Q3-Audit", "external-range", "pci"]);
  });

  it("drops empty entries from stray or trailing commas", () => {
    expect(parseTagList("a,,b,")).toEqual(["a", "b"]);
    expect(parseTagList("")).toEqual([]);
    expect(parseTagList("   ")).toEqual([]);
  });

  it("dedupes case-sensitively, keeping the first spelling", () => {
    expect(parseTagList("pci, PCI, pci")).toEqual(["pci", "PCI"]);
  });
});
