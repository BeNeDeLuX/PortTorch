import { describe, expect, it } from "vitest";
import { LAYOUT_WIDTHS, parseLayoutWidth } from "./layoutWidth";

describe("parseLayoutWidth", () => {
  it("accepts every width the app ships", () => {
    for (const width of LAYOUT_WIDTHS) {
      expect(parseLayoutWidth(width)).toBe(width);
    }
  });

  // Null is "never chosen on this browser", which is what lets the
  // account preference seed it - both still render as standard.
  it("falls back to standard for anything else", () => {
    expect(parseLayoutWidth(null)).toBe("standard");
    expect(parseLayoutWidth("")).toBe("standard");
    expect(parseLayoutWidth("ultrawide")).toBe("standard");
    expect(parseLayoutWidth("WIDE")).toBe("standard");
  });
});
