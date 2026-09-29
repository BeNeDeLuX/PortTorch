import { describe, expect, it } from "vitest";
import { ipv4PrefixToCidr, isQuickSearchShortcut, looksLikeCve, matchPages, scorePage } from "./quickSearch";
import { flatPages } from "./navigation";

const key = (over: Partial<KeyboardEvent>) => ({ key: "k", ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...over });

describe("isQuickSearchShortcut", () => {
  it("opens on Ctrl+K and Cmd+K only", () => {
    expect(isQuickSearchShortcut(key({ ctrlKey: true }))).toBe(true);
    expect(isQuickSearchShortcut(key({ metaKey: true, key: "K" }))).toBe(true);
    expect(isQuickSearchShortcut(key({}))).toBe(false);
    expect(isQuickSearchShortcut(key({ ctrlKey: true, shiftKey: true }))).toBe(false);
    expect(isQuickSearchShortcut(key({ ctrlKey: true, key: "j" }))).toBe(false);
  });
});

describe("looksLikeCve", () => {
  it("recognises a CVE id in any case, with surrounding space", () => {
    expect(looksLikeCve(" cve-2021-44228 ")).toBe(true);
    expect(looksLikeCve("CVE-2024-123456")).toBe(true);
    expect(looksLikeCve("CVE-2024")).toBe(false);
    expect(looksLikeCve("10.0.0.1")).toBe(false);
  });
});

describe("ipv4PrefixToCidr", () => {
  it("reads a partly typed address as the block it names", () => {
    expect(ipv4PrefixToCidr("10.20.41")).toBe("10.20.41.0/24");
    expect(ipv4PrefixToCidr("10.20.41.")).toBe("10.20.41.0/24");
    expect(ipv4PrefixToCidr("172.16")).toBe("172.16.0.0/16");
    expect(ipv4PrefixToCidr(" 10. ")).toBe("10.0.0.0/8");
  });

  it("leaves everything else to the free-text search", () => {
    // A bare number is as likely a port or a version as a network.
    expect(ipv4PrefixToCidr("22")).toBeNull();
    // A full address already matches exactly.
    expect(ipv4PrefixToCidr("10.20.41.9")).toBeNull();
    expect(ipv4PrefixToCidr("10.300.1")).toBeNull();
    expect(ipv4PrefixToCidr("10.0.0.0/8")).toBeNull();
    expect(ipv4PrefixToCidr("web.internal")).toBeNull();
  });
});

describe("page matching", () => {
  const pages = flatPages("operator");

  it("needs every word to match, and ranks a label match above a keyword", () => {
    expect(matchPages(pages, "scan hist").map((p) => p.label)).toEqual(["Scan History"]);
    expect(matchPages(pages, "cve")[0].label).toBe("Vulnerabilities");
    expect(scorePage({ label: "Subnets", keywords: "networks" }, "sub")).toBeGreaterThan(
      scorePage({ label: "Network Coverage", keywords: "subnet" }, "sub")
    );
    expect(matchPages(pages, "zzz")).toEqual([]);
  });

  it("offers admin pages only to an admin", () => {
    expect(matchPages(flatPages("operator"), "settings")).toEqual([]);
    expect(matchPages(flatPages("admin"), "settings")[0].to).toBe("/settings");
  });

  it("includes the account page, which is not in the menu", () => {
    expect(matchPages(pages, "password")[0].to).toBe("/account");
  });
});
