import { describe, expect, it } from "vitest";
import type { PatchPriorityHost } from "../api";
import { rankHosts } from "./patchPriority";

const now = new Date("2026-10-15T12:00:00Z");
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000).toISOString();
const host = (over: Partial<PatchPriorityHost>): PatchPriorityHost => ({
  id: over.ip ?? "x",
  ip: "10.0.0.1",
  hostname: null,
  scanner: "s",
  bootTime: null,
  uptimeSource: null,
  uptimeObservedAt: null,
  cveCount: 0,
  maxCvss: null,
  kevIds: [],
  software: [],
  ...over,
});

describe("rankHosts", () => {
  it("puts exploitation above severity above age", () => {
    const ranked = rankHosts(
      [
        host({ ip: "10.0.0.3", bootTime: daysAgo(400) }),
        host({ ip: "10.0.0.2", cveCount: 3, maxCvss: 9.8 }),
        host({ ip: "10.0.0.1", cveCount: 1, maxCvss: 7.5, kevIds: ["CVE-2024-3400"] }),
      ],
      now
    );
    expect(ranked.map((h) => h.ip)).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    expect(ranked[2].reasons.map((r) => r.kind)).toEqual(["uptime"]);
  });

  it("counts end of life and versions behind the fleet", () => {
    const [h] = rankHosts(
      [host({ software: [{ product: "PHP", version: "7.4.33", source: "service", newerInFleet: null }, { product: "USW-Enterprise-8-PoE", version: "7.5.10.17129", source: "snmp", newerInFleet: "7.5.15.17146" }] })],
      now
    );
    expect(h.reasons.map((r) => r.kind).sort()).toEqual(["behind_fleet", "eol"]);
    expect(h.score).toBe(55);
  });

  it("leaves out hosts with nothing to report", () => {
    expect(rankHosts([host({ bootTime: daysAgo(20) }), host({ software: [{ product: "nginx", version: "1.27.0", source: "service", newerInFleet: null }] })], now)).toEqual([]);
  });
});
