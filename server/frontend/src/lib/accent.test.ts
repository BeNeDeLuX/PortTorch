import { describe, expect, it } from "vitest";
import { ACCENT_COLORS, parseAccent } from "./accent";

describe("parseAccent", () => {
  it("accepts every colour the app actually ships", () => {
    for (const accent of ACCENT_COLORS) {
      expect(parseAccent(accent)).toBe(accent);
    }
  });

  // The case the old hand-written check got wrong by construction: a
  // colour added to the list but forgotten in the check read as orange,
  // so the browser silently ignored a perfectly valid stored choice.
  it("keeps the newer colours rather than falling back", () => {
    expect(parseAccent("lila")).toBe("lila");
    expect(parseAccent("pink")).toBe("pink");
    expect(parseAccent("evening")).toBe("evening");
  });

  // A browser can hold an accent this build no longer ships, and nothing
  // ever writes null - that is "never chosen" - so both mean the default.
  it("falls back to orange for anything unknown", () => {
    expect(parseAccent(null)).toBe("orange");
    expect(parseAccent("")).toBe("orange");
    expect(parseAccent("teal")).toBe("orange");
    expect(parseAccent("ORANGE")).toBe("orange");
  });
});
