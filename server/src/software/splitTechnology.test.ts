import { describe, expect, it } from "vitest";
import { splitTechnology } from "./routes";

// gowitness packs a technology and its version into one string as
// "Name:Version", which has to come apart into the same product/version
// shape nmap reports - without mangling a name that merely contains a
// colon. Pure string handling, no database, same category as lib/cron's
// own tests.
describe("splitTechnology", () => {
  it("splits a real Name:Version pair", () => {
    expect(splitTechnology("Nginx:1.30.3")).toEqual({ product: "Nginx", version: "1.30.3" });
    expect(splitTechnology("jQuery:3.7.1")).toEqual({ product: "jQuery", version: "3.7.1" });
    expect(splitTechnology("PHP:8.3.33")).toEqual({ product: "PHP", version: "8.3.33" });
    // A bare major version is still a version.
    expect(splitTechnology("Vue.js:5")).toEqual({ product: "Vue.js", version: "5" });
  });

  it("leaves a plain name alone", () => {
    expect(splitTechnology("Forgejo")).toEqual({ product: "Forgejo", version: null });
    expect(splitTechnology("Microsoft ASP.NET")).toEqual({ product: "Microsoft ASP.NET", version: null });
  });

  it("does not split when what follows the colon is not a version", () => {
    // The case that makes this worth a function rather than a split(":"):
    // a name carrying a colon would otherwise lose half of itself, and
    // the wrong half would be shown as a version.
    expect(splitTechnology("Forgejo: Beyond coding")).toEqual({
      product: "Forgejo: Beyond coding",
      version: null,
    });
    expect(splitTechnology("Something:alpha")).toEqual({ product: "Something:alpha", version: null });
  });

  it("splits on the last colon, since a version cannot contain one", () => {
    expect(splitTechnology("Some:Product:2.1")).toEqual({ product: "Some:Product", version: "2.1" });
  });

  it("handles degenerate input without producing an empty product", () => {
    expect(splitTechnology(":1.2.3")).toEqual({ product: ":1.2.3", version: null });
    expect(splitTechnology("Trailing:")).toEqual({ product: "Trailing:", version: null });
    expect(splitTechnology("  Padded:2.0  ")).toEqual({ product: "Padded", version: "2.0" });
  });

  it("keeps version strings that carry build metadata", () => {
    expect(splitTechnology("Jetty:9.4.53.v20231009")).toEqual({
      product: "Jetty",
      version: "9.4.53.v20231009",
    });
  });
});
