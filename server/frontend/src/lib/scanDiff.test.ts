import { describe, expect, it } from "vitest";
import { HostPortObservation } from "../api";
import { changesInRun, diffScans, scanRuns } from "./scanDiff";

function obs(overrides: Partial<HostPortObservation>): HostPortObservation {
  return {
    port: 80,
    protocol: "tcp",
    state: "open",
    service_name: "http",
    service_product: null,
    service_version: null,
    observed_at: "2026-09-01T10:00:00Z",
    scan_job_id: "job-1",
    scanner_agent_name: "scanner-a",
    ...overrides,
  };
}

describe("scanRuns", () => {
  it("lists one entry per scan job, newest first, with its port count", () => {
    const runs = scanRuns([
      obs({ scan_job_id: "old", observed_at: "2026-09-01T10:00:00Z", port: 80 }),
      obs({ scan_job_id: "old", observed_at: "2026-09-01T10:00:00Z", port: 443 }),
      obs({ scan_job_id: "new", observed_at: "2026-09-05T10:00:00Z", port: 80 }),
    ]);
    expect(runs.map((r) => r.scanJobId)).toEqual(["new", "old"]);
    expect(runs[1].portCount).toBe(2);
    expect(runs[0].scannerAgentName).toBe("scanner-a");
  });
});

describe("diffScans", () => {
  const T1 = "2026-09-01T10:00:00Z";
  const T2 = "2026-09-02T10:00:00Z";
  const history: HostPortObservation[] = [
    // Before: 22 and 80 open, 443 recorded closed.
    obs({ scan_job_id: "before", observed_at: T1, port: 22, service_name: "ssh" }),
    obs({ scan_job_id: "before", observed_at: T1, port: 80, service_name: "http", service_product: "nginx", service_version: "1.18.0" }),
    obs({ scan_job_id: "before", observed_at: T1, port: 443, state: "closed", service_name: null }),
    // After: 22 recorded closed, 80 upgraded, 443 now open, 3389 new.
    obs({ scan_job_id: "after", observed_at: T2, port: 22, state: "closed", service_name: null }),
    obs({ scan_job_id: "after", observed_at: T2, port: 80, service_name: "http", service_product: "nginx", service_version: "1.24.0" }),
    obs({ scan_job_id: "after", observed_at: T2, port: 443, service_name: "https" }),
    obs({ scan_job_id: "after", observed_at: T2, port: 3389, service_name: "ms-wbt-server" }),
  ];

  it("reports what opened, closed and changed between two runs", () => {
    const changes = diffScans(history, "before", "after");
    const byPort = Object.fromEntries(changes.map((c) => [c.port, c]));

    expect(byPort[3389].kind).toBe("opened");
    // Recorded closed before, open after - that is an opening, even
    // though a row existed for it in both scans.
    expect(byPort[443].kind).toBe("opened");
    expect(byPort[22].kind).toBe("closed");
    expect(byPort[80].kind).toBe("changed");
    expect(byPort[80].details).toEqual(["version nginx 1.18.0 → nginx 1.24.0"]);
  });

  it("never reports a port as closed because a later scan did not ask about it", () => {
    // The case this exists for: a full scan, then targeted scans of single
    // ports. Port 22 is only in the first, but is still open afterwards.
    const targeted: HostPortObservation[] = [
      obs({ scan_job_id: "full", observed_at: T1, port: 22, service_name: "ssh", scan_port_spec: "1-1024" }),
      obs({ scan_job_id: "full", observed_at: T1, port: 25, service_name: "smtp", scan_port_spec: "1-1024" }),
      obs({ scan_job_id: "only80", observed_at: T2, port: 80, service_name: "http", scan_port_spec: "80" }),
      obs({ scan_job_id: "only143", observed_at: "2026-09-03T10:00:00Z", port: 143, service_name: "imap", scan_port_spec: "143" }),
    ];
    const between = diffScans(targeted, "full", "only143");
    expect(between.filter((c) => c.kind === "closed")).toEqual([]);
    expect(between.filter((c) => c.kind === "opened").map((c) => c.port)).toEqual([80, 143]);
    expect(between.filter((c) => c.kind === "unchanged").map((c) => c.port)).toEqual([22, 25]);

    // And a single run's own changes are just what it found.
    expect(changesInRun(targeted, "only143").map((c) => `${c.kind} ${c.port}`)).toEqual(["opened 143"]);
    expect(changesInRun(targeted, "only80").map((c) => `${c.kind} ${c.port}`)).toEqual(["opened 80"]);
  });

  it("reports a close only from a scan that recorded one", () => {
    const h: HostPortObservation[] = [
      obs({ scan_job_id: "a", observed_at: T1, port: 22 }),
      obs({ scan_job_id: "a", observed_at: T1, port: 25 }),
      obs({ scan_job_id: "b", observed_at: T2, port: 25, state: "closed" }),
    ];
    expect(changesInRun(h, "b").map((c) => `${c.kind} ${c.port}`)).toEqual(["closed 25"]);
  });

  it("orders by what matters: opened, then closed, then changed", () => {
    const kinds = diffScans(history, "before", "after").map((c) => c.kind);
    expect(kinds.indexOf("opened")).toBeLessThan(kinds.indexOf("closed"));
    expect(kinds.indexOf("closed")).toBeLessThan(kinds.indexOf("changed"));
  });

  it("says nothing about a port that was not open in either run", () => {
    const changes = diffScans(
      [
        obs({ scan_job_id: "before", port: 8080, state: "closed" }),
        obs({ scan_job_id: "after", observed_at: "2026-09-02T10:00:00Z", port: 8080, state: "filtered" }),
      ],
      "before",
      "after"
    );
    // Both mean "not open" - reporting a change here would be noise.
    expect(changes).toHaveLength(0);
  });

  it("keeps a port that is open and identical in both as unchanged", () => {
    const changes = diffScans(
      [obs({ scan_job_id: "before", port: 22 }), obs({ scan_job_id: "after", observed_at: "2026-09-02T10:00:00Z", port: 22 })],
      "before",
      "after"
    );
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe("unchanged");
    expect(changes[0].details).toEqual([]);
  });

  it("treats the same port number on two protocols separately", () => {
    const changes = diffScans(
      [
        obs({ scan_job_id: "before", port: 53, protocol: "tcp" }),
        obs({ scan_job_id: "after", observed_at: "2026-09-02T10:00:00Z", port: 53, protocol: "tcp" }),
        obs({ scan_job_id: "after", observed_at: "2026-09-02T10:00:00Z", port: 53, protocol: "udp" }),
      ],
      "before",
      "after"
    );
    // TCP/53 unchanged, UDP/53 newly open - a single-key diff would have
    // collapsed these into one row and lost the opening.
    expect(changes.filter((c) => c.kind === "opened")).toHaveLength(1);
    expect(changes.find((c) => c.kind === "opened")?.protocol).toBe("udp");
  });
});
