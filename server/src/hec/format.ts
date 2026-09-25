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

// A host as one event: the asset record the port events hang off.
//
// The observation stream carries the port level completely and nothing
// about the machine - OS, device type, manufacturer and tags all live on
// `hosts`, not on an observation - so a SIEM could chart services and
// software and none of the inventory dimensions. This is the lookup that
// closes that: one event per host, re-sent whenever a scan refreshes it,
// keyed on the same host_id and ip the port events carry.
//
// Timestamped with last_seen_at rather than "now", so a host that has not
// been seen in a month lands in the SIEM at the time it was actually last
// confirmed.
export function hostEvent(
  row: {
    id: string;
    ip: unknown;
    hostname: string | null;
    os_name: string | null;
    os_family: string | null;
    os_vendor: string | null;
    device_type: string | null;
    os_accuracy: number | null;
    mac_address: string | null;
    mac_vendor: string | null;
    derived_hostname: string | null;
    derived_hostname_source: string | null;
    derived_mac_address: string | null;
    derived_mac_vendor: string | null;
    derived_mac_source: string | null;
    first_seen_at: Date | string;
    last_seen_at: Date | string;
    retired_at: Date | string | null;
    scanner_agent_name: string | null;
    tags: string[] | null;
  },
  settings: HecSettings
): HecEvent {
  return {
    time: toEpochSeconds(row.last_seen_at),
    source: "porttorch:host",
    sourcetype: settings.sourcetype || "porttorch:host",
    ...(settings.index ? { index: settings.index } : {}),
    event: {
      host_id: row.id,
      ip: String(row.ip),
      hostname: row.hostname,
      os_name: row.os_name,
      os_family: row.os_family,
      os_vendor: row.os_vendor,
      device_type: row.device_type,
      os_accuracy: row.os_accuracy,
      mac_address: row.mac_address,
      mac_vendor: row.mac_vendor,
      // Sent alongside rather than merged into the fields above: a SIEM
      // correlating on a name needs to know whether it came from DNS or
      // from the machine's own claim about itself.
      derived_hostname: row.derived_hostname,
      derived_hostname_source: row.derived_hostname_source,
      derived_mac_address: row.derived_mac_address,
      derived_mac_vendor: row.derived_mac_vendor,
      derived_mac_source: row.derived_mac_source,
      scanner_agent_name: row.scanner_agent_name,
      first_seen_at: new Date(row.first_seen_at).toISOString(),
      last_seen_at: new Date(row.last_seen_at).toISOString(),
      // Carried as a boolean rather than only a timestamp: "is this
      // decommissioned" is the question a correlation search asks, and
      // making every consumer derive it from a nullable date is how two
      // of them end up deriving it differently.
      retired: row.retired_at !== null,
      retired_at: row.retired_at ? new Date(row.retired_at).toISOString() : null,
      tags: row.tags ?? [],
    },
  };
}

// One captured certificate as one event. Sent per capture rather than per
// (host, port): tls_certificates is append-only, so this is the history of
// what each port presented, and a SIEM that wants only the current one
// takes the latest per host_id+port - the same reduction the certificates
// page performs.
export function certificateEvent(
  row: {
    id: string | number;
    host_id: string;
    ip: unknown;
    hostname: string | null;
    scan_job_id: string;
    port: number;
    subject_cn: string | null;
    issuer_cn: string | null;
    san_list: string[] | null;
    not_before: Date | string | null;
    not_after: Date | string | null;
    fingerprint_sha256: string;
    signature_algorithm: string | null;
    self_signed: boolean;
    tls_version: string | null;
    cipher_suite: string | null;
    key_algorithm: string | null;
    key_bits: number | null;
    captured_at: Date | string;
    scanner_agent_name: string | null;
  },
  settings: HecSettings
): HecEvent {
  return {
    time: toEpochSeconds(row.captured_at),
    source: "porttorch:certificate",
    sourcetype: settings.sourcetype || "porttorch:certificate",
    ...(settings.index ? { index: settings.index } : {}),
    event: {
      certificate_id: String(row.id),
      host_id: row.host_id,
      ip: String(row.ip),
      hostname: row.hostname,
      scan_job_id: row.scan_job_id,
      scanner_agent_name: row.scanner_agent_name,
      port: row.port,
      subject_cn: row.subject_cn,
      issuer_cn: row.issuer_cn,
      san_list: row.san_list ?? [],
      not_before: row.not_before ? new Date(row.not_before).toISOString() : null,
      not_after: row.not_after ? new Date(row.not_after).toISOString() : null,
      fingerprint_sha256: row.fingerprint_sha256,
      signature_algorithm: row.signature_algorithm,
      self_signed: row.self_signed,
      tls_version: row.tls_version,
      cipher_suite: row.cipher_suite,
      key_algorithm: row.key_algorithm,
      key_bits: row.key_bits,
    },
  };
}

// HEC's body format: JSON objects one after another, not an array and not
// comma-separated. Newlines are only for readability - the collector
// parses object-by-object either way.
export function serializeBatch(events: HecEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n");
}
