import type { HecSettings } from "../settings/appSettings";

// One HEC event envelope. Splunk's collector (and the several others that
// speak its shape) takes a stream of these - concatenated JSON objects,
// deliberately *not* a JSON array, which is what "\n"-joining below is
// for rather than JSON.stringify on a list.
export interface HecEvent {
  // Seconds since the epoch, with millisecond precision. HEC accepts a
  // fractional number here; sending a string works on Splunk but is
  // rejected by some other collectors, so it stays numeric.
  time: number;
  source: string;
  sourcetype: string;
  index?: string;
  event: Record<string, unknown>;
}

export function toEpochSeconds(value: Date | string): number {
  return new Date(value).getTime() / 1000;
}

// A row of audit_log as one event. The field names are kept exactly as
// they are in the database rather than renamed to a SIEM's own
// conventions: whoever writes the correlation searches has this
// codebase's own docs to read, and a private renaming layer would be one
// more thing to keep in sync.
export function auditEvent(
  row: { id: string | number; event: string; actor: string | null; source_ip: string | null; details: unknown; created_at: Date | string },
  settings: HecSettings
): HecEvent {
  return {
    time: toEpochSeconds(row.created_at),
    source: "porttorch:audit",
    sourcetype: settings.sourcetype || "porttorch:audit",
    ...(settings.index ? { index: settings.index } : {}),
    event: {
      audit_id: String(row.id),
      event: row.event,
      actor: row.actor,
      source_ip: row.source_ip,
      details: row.details ?? null,
    },
  };
}

// One event per *log line*, not one per scan job. A SIEM indexes events,
// and a single blob holding a thousand lines of one scan would be one
// unsearchable event - the whole point of forwarding these is being able
// to search them.
export function scanLogEvents(
  row: { scan_job_id: string; logs: unknown; created_at: Date | string },
  settings: HecSettings,
  jobMeta: { scanner_agent_name: string | null; target_spec: string; port_spec: string } | undefined
): HecEvent[] {
  const lines = Array.isArray(row.logs) ? row.logs : [];
  return lines.map((line) => {
    const l = (line ?? {}) as { time?: unknown; stage?: unknown; message?: unknown };
    // The scanner stamps each line itself; fall back to when the log was
    // uploaded if a line ever arrives without a usable one, rather than
    // dropping the line or letting the collector stamp it "now".
    const stamped = typeof l.time === "string" && !Number.isNaN(new Date(l.time).getTime()) ? l.time : row.created_at;
    return {
      time: toEpochSeconds(stamped),
      source: "porttorch:scan",
      sourcetype: settings.sourcetype || "porttorch:scan",
      ...(settings.index ? { index: settings.index } : {}),
      event: {
        scan_job_id: row.scan_job_id,
        scanner_agent_name: jobMeta?.scanner_agent_name ?? null,
        target_spec: jobMeta?.target_spec ?? null,
        port_spec: jobMeta?.port_spec ?? null,
        stage: typeof l.stage === "string" ? l.stage : null,
        message: typeof l.message === "string" ? l.message : String(l.message ?? ""),
      },
    };
  });
}

// One port observation as one event - the scan result itself, which is
// what a SIEM actually wants and is the one thing these streams did not
// carry. The audit trail says who pressed what and the scan log says what
// the scanner was doing; neither says that 3389 opened on a server.
//
// host_port_observations is append-only with a bigserial key, so this
// pages exactly like the audit stream does. Closed observations are
// included deliberately: a port that stopped answering is a change worth
// correlating, and dropping it would make the feed a list of things that
// exist rather than a record of what changed.
export function observationEvent(
  row: {
    id: string | number;
    host_id: string;
    ip: unknown;
    hostname: string | null;
    scan_job_id: string;
    port: number;
    protocol: string;
    state: string;
    service_name: string | null;
    service_product: string | null;
    service_version: string | null;
    banner: string | null;
    observed_at: Date | string;
    scanner_agent_name: string | null;
  },
  settings: HecSettings
): HecEvent {
  return {
    time: toEpochSeconds(row.observed_at),
    source: "porttorch:observation",
    sourcetype: settings.sourcetype || "porttorch:observation",
    ...(settings.index ? { index: settings.index } : {}),
    event: {
      observation_id: String(row.id),
      host_id: row.host_id,
      ip: String(row.ip),
      hostname: row.hostname,
      scan_job_id: row.scan_job_id,
      scanner_agent_name: row.scanner_agent_name,
      port: row.port,
      protocol: row.protocol,
      state: row.state,
      service_name: row.service_name,
      service_product: row.service_product,
      service_version: row.service_version,
      banner: row.banner,
    },
  };
}

// One nuclei match as one event. severity is carried as nuclei's own
// value rather than mapped onto a SIEM's severity scale - the mapping
// belongs wherever the correlation searches live, and inventing one here
// would be a private convention nobody else shares.
export function findingEvent(
  row: {
    id: string;
    host_id: string;
    ip: unknown;
    hostname: string | null;
    scan_job_id: string;
    port: number;
    template_id: string;
    name: string;
    severity: string;
    matched_at: string;
    tags: string[] | null;
    observed_at: Date | string;
    scanner_agent_name: string | null;
  },
  settings: HecSettings
): HecEvent {
  return {
    time: toEpochSeconds(row.observed_at),
    source: "porttorch:finding",
    sourcetype: settings.sourcetype || "porttorch:finding",
    ...(settings.index ? { index: settings.index } : {}),
    event: {
      finding_id: row.id,
      host_id: row.host_id,
      ip: String(row.ip),
      hostname: row.hostname,
      scan_job_id: row.scan_job_id,
      scanner_agent_name: row.scanner_agent_name,
      port: row.port,
      template_id: row.template_id,
      name: row.name,
      severity: row.severity,
      matched_at: row.matched_at,
      tags: row.tags ?? [],
    },
  };
}

// HEC's body format: JSON objects one after another, not an array and not
// comma-separated. Newlines are only for readability - the collector
// parses object-by-object either way.
export function serializeBatch(events: HecEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n");
}
