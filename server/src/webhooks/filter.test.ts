import { describe, expect, it } from "vitest";
import { severityRank, shouldDeliver } from "./filter";

const none = { filter_scanner_agent_ids: [], filter_tags: [], min_severity: null };

describe("shouldDeliver", () => {
  it("delivers everything to a channel with no filters", () => {
    // Every channel that predates filters has exactly this shape, so this
    // is the "nothing changed" case.
    expect(shouldDeliver(none, {})).toBe(true);
    expect(shouldDeliver(none, { scannerAgentId: "a", hostTags: ["prod"], severity: "info" })).toBe(true);
  });

  it("narrows by scanner", () => {
    const f = { ...none, filter_scanner_agent_ids: ["a", "b"] };
    expect(shouldDeliver(f, { scannerAgentId: "a" })).toBe(true);
    expect(shouldDeliver(f, { scannerAgentId: "c" })).toBe(false);
  });

  it("matches any of the listed tags, not all of them", () => {
    const f = { ...none, filter_tags: ["prod", "dmz"] };
    expect(shouldDeliver(f, { hostTags: ["dmz", "linux"] })).toBe(true);
    expect(shouldDeliver(f, { hostTags: ["staging"] })).toBe(false);
    expect(shouldDeliver(f, { hostTags: [] })).toBe(false);
  });

  it("never suppresses an alert that carries no host, even with host filters set", () => {
    // The load-bearing rule. scanner.offline and scan_queue.backlog are
    // about the fleet - swallowing them because a channel was narrowed to
    // "prod" would cost an operator exactly the alerts that matter most,
    // while looking like they had only reduced the noisy ones.
    const f = { ...none, filter_tags: ["prod"] };
    expect(shouldDeliver(f, {})).toBe(true);
    expect(shouldDeliver(f, { scannerAgentId: "a" })).toBe(true);
  });

  it("applies a severity minimum only to alerts that carry one", () => {
    const f = { ...none, min_severity: "high" };
    expect(shouldDeliver(f, { severity: "critical" })).toBe(true);
    expect(shouldDeliver(f, { severity: "high" })).toBe(true);
    expect(shouldDeliver(f, { severity: "medium" })).toBe(false);
    expect(shouldDeliver(f, { severity: "info" })).toBe(false);
    // A CVE alert spans many hosts and carries no single severity - it
    // must not be silently dropped by a minimum meant for nuclei.
    expect(shouldDeliver(f, {})).toBe(true);
  });

  it("lets an unrecognised severity through a minimum", () => {
    // Being told about something we could not classify is the safe
    // direction to fail.
    expect(shouldDeliver({ ...none, min_severity: "critical" }, { severity: "weird" })).toBe(true);
  });

  it("ranks nuclei's own scale, with unknown weakest", () => {
    expect(severityRank("unknown")).toBeLessThan(severityRank("info"));
    expect(severityRank("info")).toBeLessThan(severityRank("critical"));
    expect(severityRank("HIGH")).toBe(severityRank("high"));
    expect(severityRank(null)).toBe(-1);
  });

  it("combines filters as AND", () => {
    const f = { filter_scanner_agent_ids: ["a"], filter_tags: ["prod"], min_severity: "high" };
    expect(shouldDeliver(f, { scannerAgentId: "a", hostTags: ["prod"], severity: "high" })).toBe(true);
    expect(shouldDeliver(f, { scannerAgentId: "a", hostTags: ["prod"], severity: "low" })).toBe(false);
    expect(shouldDeliver(f, { scannerAgentId: "b", hostTags: ["prod"], severity: "high" })).toBe(false);
  });
});
