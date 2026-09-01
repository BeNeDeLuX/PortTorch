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

// HEC's body format: JSON objects one after another, not an array and not
// comma-separated. Newlines are only for readability - the collector
// parses object-by-object either way.
export function serializeBatch(events: HecEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n");
}
