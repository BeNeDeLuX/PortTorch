import { describe, expect, it } from "vitest";
import type { ScannerAgent } from "../api";
import { MIN_SCANNER_VERSION, capabilitySupport } from "./scannerCapabilities";

function agent(version: string | null): ScannerAgent {
  return {
    id: "00000000-0000-0000-0000-000000000000",
    name: "test-agent",
    last_seen_at: null,
    last_seen_ip: null,
    version,
    created_at: "2026-01-01T00:00:00.000Z",
    revoked_at: null,
    update_requested_at: null,
    update_request_status: null,
    update_failure_reason: null,
    submit_queue_pending: null,
  };
}

describe("capabilitySupport", () => {
  it("accepts exactly the minimum version, not just newer ones", () => {
    expect(capabilitySupport(agent(MIN_SCANNER_VERSION.scanRate), "scanRate")).toBe("supported");
  });

  it("accepts newer versions, including across a minor bump", () => {
    expect(capabilitySupport(agent("0.9.3"), "scanRate")).toBe("supported");
    expect(capabilitySupport(agent("0.10.0"), "scanRate")).toBe("supported");
    expect(capabilitySupport(agent("1.0.0"), "scanRate")).toBe("supported");
  });

  it("rejects the version immediately below the minimum", () => {
    // 0.9.1 is the last release that silently ignored masscan_rate - the
    // exact case this check exists for.
    expect(capabilitySupport(agent("0.9.1"), "scanRate")).toBe("too-old");
    expect(capabilitySupport(agent("0.8.9"), "scanRate")).toBe("too-old");
  });

  it("compares numerically, not lexically", () => {
    // A naive string compare would rank "0.10.0" below "0.9.2" (since "1"
    // < "9" at the third character) and wrongly warn that a much newer
    // scanner is too old. Both of these are above the 0.9.2 minimum.
    expect(capabilitySupport(agent("0.10.0"), "scanRate")).toBe("supported");
    expect(capabilitySupport(agent("0.9.9"), "scanRate")).toBe("supported");
  });

  it("reports 'unknown' - not 'too-old' - for an agent that has never reported a version", () => {
    // scanner_agents.version stays null until that scanner makes its first
    // authenticated request, so a freshly created agent isn't evidence of
    // an old build; the two cases are phrased differently in the UI.
    expect(capabilitySupport(agent(null), "scanRate")).toBe("unknown");
  });

  it("reports 'unknown' when no agent is selected at all", () => {
    expect(capabilitySupport(undefined, "scanRate")).toBe("unknown");
  });
});
