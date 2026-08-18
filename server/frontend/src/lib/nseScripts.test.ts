import { describe, expect, it } from "vitest";
import {
  ACTIVE_SCRIPTS,
  ADDITIONAL_SAFE_NSE_SCRIPTS,
  ALL_SAFE_NSE_SCRIPTS,
  DEFAULT_NSE_SCRIPTS,
  groupActiveNseScripts,
  groupAdditionalNseScripts,
} from "./nseScripts";

describe("ADDITIONAL_SAFE_NSE_SCRIPTS", () => {
  it("is All Safe minus whatever Default already covers, so the page never shows a script twice", () => {
    for (const script of DEFAULT_NSE_SCRIPTS) {
      expect(ADDITIONAL_SAFE_NSE_SCRIPTS).not.toContain(script);
    }
    // Every remaining entry still came from the All Safe list.
    for (const script of ADDITIONAL_SAFE_NSE_SCRIPTS) {
      expect(ALL_SAFE_NSE_SCRIPTS).toContain(script);
    }
  });
});

describe("groupAdditionalNseScripts", () => {
  it("places every input script in exactly one group - none lost, none duplicated", () => {
    const groups = groupAdditionalNseScripts();
    const grouped = groups.flatMap((g) => g.scripts);
    expect(grouped.sort()).toEqual([...ADDITIONAL_SAFE_NSE_SCRIPTS].sort());
    expect(new Set(grouped).size).toBe(grouped.length);
  });

  it("omits groups that matched nothing rather than rendering empty sections", () => {
    for (const group of groupAdditionalNseScripts()) {
      expect(group.scripts.length).toBeGreaterThan(0);
    }
  });

  it("always puts the 'Other' catch-all last, so the layout doesn't reshuffle", () => {
    const groups = groupAdditionalNseScripts(["http-title", "definitely-not-a-real-script"]);
    expect(groups[groups.length - 1].name).toBe("Other");
    expect(groups[groups.length - 1].scripts).toEqual(["definitely-not-a-real-script"]);
  });

  it("assigns a script to the first matching rule, in declaration order", () => {
    const groups = groupAdditionalNseScripts(["http-title", "dns-nsid", "ssl-cert", "afp-ls"]);
    expect(groups.map((g) => g.name)).toEqual(["HTTP / Web", "DNS", "SSL / TLS", "AFP / Apple"]);
  });

  it("is deterministic across calls", () => {
    expect(groupAdditionalNseScripts()).toEqual(groupAdditionalNseScripts());
  });

  it("returns nothing at all for an empty input, rather than a list of empty groups", () => {
    expect(groupAdditionalNseScripts([])).toEqual([]);
  });
});

describe("groupActiveNseScripts", () => {
  it("splits the Active tier into nmap's own four categories, all non-empty", () => {
    const groups = groupActiveNseScripts();
    expect(groups.map((g) => g.name)).toEqual(["Exploit", "Brute-force", "Denial of Service", "Other Intrusive"]);
    for (const group of groups) {
      expect(group.scripts.length).toBeGreaterThan(0);
    }
  });

  // Not an oversight in the lists: nmap genuinely tags these six as both
  // `exploit` and `dos`, so they legitimately appear under two headings.
  // Harmless in the UI - React keys are scoped per group, and both
  // checkboxes bind to the same entry in the selected-scripts Set, so
  // ticking one ticks the other. Asserted explicitly so that if the lists
  // are ever regenerated and the overlap changes, it's a deliberate
  // decision rather than a silent shift.
  it("only ever double-lists a script that nmap itself puts in two categories", () => {
    const all = groupActiveNseScripts().flatMap((g) => g.scripts);
    const seen = new Map<string, number>();
    for (const script of all) seen.set(script, (seen.get(script) ?? 0) + 1);
    const duplicated = [...seen].filter(([, count]) => count > 1).map(([script]) => script);
    expect(duplicated.sort()).toEqual([
      "smb-vuln-conficker",
      "smb-vuln-cve2009-3103",
      "smb-vuln-ms06-025",
      "smb-vuln-ms07-029",
      "smb-vuln-ms08-067",
      "smb-vuln-regsvc-dos",
    ]);
    for (const script of duplicated) {
      const groups = groupActiveNseScripts().filter((g) => g.scripts.includes(script));
      expect(groups.map((g) => g.name)).toEqual(["Exploit", "Denial of Service"]);
    }
  });

  it("keeps ACTIVE_SCRIPTS in sync with the grouped lists, since the warning badge keys off it", () => {
    // ACTIVE_SCRIPTS is a Set, so it holds the deduplicated union - the
    // right comparison is against the unique scripts, not the flat count.
    const all = groupActiveNseScripts().flatMap((g) => g.scripts);
    expect([...ACTIVE_SCRIPTS].sort()).toEqual([...new Set(all)].sort());
  });

  it("never overlaps the Default tier - an active script must be opt-in only", () => {
    for (const script of ACTIVE_SCRIPTS) {
      expect(DEFAULT_NSE_SCRIPTS).not.toContain(script);
    }
  });
});
