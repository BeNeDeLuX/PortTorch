import { describe, expect, it } from "vitest";
import { collectorUrl } from "./client";
import { auditEvent, scanLogEvents, serializeBatch, toEpochSeconds } from "./format";
import type { HecSettings } from "../settings/appSettings";

const settings: HecSettings = {
  url: "https://splunk.invalid:8088",
  token: "t",
  auditEnabled: true,
  scanLogEnabled: true,
  index: null,
  sourcetype: null,
  verifyTls: true,
};

describe("collectorUrl", () => {
  it("appends Splunk's own collector path to a base URL", () => {
    expect(collectorUrl("https://splunk:8088")).toBe("https://splunk:8088/services/collector/event");
    expect(collectorUrl("https://splunk:8088/")).toBe("https://splunk:8088/services/collector/event");
  });

  it("leaves a URL that already names the collector alone", () => {
    // Most vendor documentation shows the full path, so admins paste it.
    expect(collectorUrl("https://splunk:8088/services/collector")).toBe("https://splunk:8088/services/collector");
    expect(collectorUrl("https://splunk:8088/services/collector/event")).toBe(
      "https://splunk:8088/services/collector/event"
    );
  });
});

describe("HEC event shape", () => {
  it("stamps time as fractional epoch seconds, not milliseconds", () => {
    // Sending milliseconds would file every event in the year 57000-odd.
    expect(toEpochSeconds("2026-01-01T00:00:00.500Z")).toBe(1767225600.5);
  });

  it("carries an audit row through with its own field names", () => {
    const e = auditEvent(
      {
        id: 42,
        event: "host.retired",
        actor: "alice",
        source_ip: "10.0.0.5",
        details: { host_id: "abc" },
        created_at: "2026-01-01T00:00:00.000Z",
      },
      settings
    );
    expect(e.source).toBe("porttorch:audit");
    expect(e.sourcetype).toBe("porttorch:audit");
    expect(e.index).toBeUndefined();
    expect(e.event).toEqual({
      audit_id: "42",
      event: "host.retired",
      actor: "alice",
      source_ip: "10.0.0.5",
      details: { host_id: "abc" },
    });
  });

  it("uses the configured index and sourcetype when set", () => {
    const e = auditEvent(
      { id: 1, event: "x", actor: null, source_ip: null, details: null, created_at: "2026-01-01T00:00:00Z" },
      { ...settings, index: "netsec", sourcetype: "custom:type" }
    );
    expect(e.index).toBe("netsec");
    expect(e.sourcetype).toBe("custom:type");
  });

  it("expands a scan log into one event per line, not one per job", () => {
    // A single blob holding a thousand lines would be one unsearchable
    // event, which defeats the point of forwarding them.
    const events = scanLogEvents(
      {
        scan_job_id: "job-1",
        logs: [
          { time: "2026-01-01T00:00:01.000Z", stage: "masscan", message: "started" },
          { time: "2026-01-01T00:00:02.000Z", stage: "nmap", message: "enriching" },
        ],
        created_at: "2026-01-01T00:05:00.000Z",
      },
      settings,
      { scanner_agent_name: "scanner-a", target_spec: "10.0.0.0/24", port_spec: "80" }
    );
    expect(events).toHaveLength(2);
    expect(events[0].time).toBe(toEpochSeconds("2026-01-01T00:00:01.000Z"));
    expect(events[0].event).toEqual({
      scan_job_id: "job-1",
      scanner_agent_name: "scanner-a",
      target_spec: "10.0.0.0/24",
      port_spec: "80",
      stage: "masscan",
      message: "started",
    });
  });

  it("falls back to the upload time for a line with no usable timestamp", () => {
    // Better than dropping the line, and better than letting the
    // collector stamp it "now" - which would bunch a whole scan's log
    // onto the moment it happened to be forwarded.
    const [e] = scanLogEvents(
      { scan_job_id: "j", logs: [{ stage: "x", message: "m" }], created_at: "2026-01-01T00:05:00.000Z" },
      settings,
      undefined
    );
    expect(e.time).toBe(toEpochSeconds("2026-01-01T00:05:00.000Z"));
    expect(e.event.scanner_agent_name).toBeNull();
  });

  it("tolerates a log column that isn't an array", () => {
    expect(scanLogEvents({ scan_job_id: "j", logs: null, created_at: "2026-01-01T00:00:00Z" }, settings, undefined)).toEqual(
      []
    );
  });
});

describe("serializeBatch", () => {
  it("concatenates JSON objects rather than producing an array", () => {
    // HEC takes a stream of objects; a JSON array is rejected.
    const body = serializeBatch([
      { time: 1, source: "s", sourcetype: "st", event: { a: 1 } },
      { time: 2, source: "s", sourcetype: "st", event: { a: 2 } },
    ]);
    expect(body.startsWith("[")).toBe(false);
    expect(body.split("\n")).toHaveLength(2);
    for (const line of body.split("\n")) expect(() => JSON.parse(line)).not.toThrow();
  });
});
