import { HostPortObservation } from "../api";

// Comparing two of a host's own scans. The data is already on the page -
// GET /api/hosts/:id returns up to 500 observations, each tagged with the
// scan job that produced it - so this is a pure derivation, no new
// endpoint, the same "client-side aggregation, not a new backend concept"
// shape as useFleetHealth.
//
// What it answers that nothing else did: the Digest shows fleet-wide
// change over a window, and the host timeline shows every scan in order.
// Neither answers "what changed on *this* host between these two scans",
// which is the question after an incident or a change window.

export interface ScanRun {
  scanJobId: string;
  observedAt: string;
  scannerAgentName: string | null;
  portCount: number;
  // The ports the run asked about, e.g. "80" or "1-1024,U:53". Null for
  // history rows that predate the field.
  portSpec: string | null;
}

export interface PortChange {
  port: number;
  protocol: string;
  before: HostPortObservation | null;
  after: HostPortObservation | null;
  kind: "opened" | "closed" | "changed" | "unchanged";
  // What actually differs, for a "changed" row - the service moved, or
  // the version did. Empty for the other kinds.
  details: string[];
}

// One entry per scan job that touched this host, newest first. Built from
// the observations rather than from scan_jobs, so it only ever lists runs
// that actually produced something for this host - a scan that covered
// the range but found nothing here would be a confusing thing to offer as
// a comparison point.
export function scanRuns(history: HostPortObservation[]): ScanRun[] {
  const byJob = new Map<string, ScanRun>();
  for (const row of history) {
    const existing = byJob.get(row.scan_job_id);
    if (existing) {
      existing.portCount++;
      if (row.observed_at > existing.observedAt) existing.observedAt = row.observed_at;
      continue;
    }
    byJob.set(row.scan_job_id, {
      scanJobId: row.scan_job_id,
      observedAt: row.observed_at,
      scannerAgentName: row.scanner_agent_name ?? null,
      portCount: 1,
      portSpec: row.scan_port_spec ?? null,
    });
  }
  return [...byJob.values()].sort((a, b) => new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime());
}

function keyOf(row: Pick<HostPortObservation, "port" | "protocol">): string {
  return `${row.port}/${row.protocol}`;
}

function runBounds(history: HostPortObservation[], jobId: string): { first: number; last: number } | null {
  let first = Infinity;
  let last = -Infinity;
  for (const row of history) {
    if (row.scan_job_id !== jobId) continue;
    const t = Date.parse(row.observed_at);
    if (t < first) first = t;
    if (t > last) last = t;
  }
  return first === Infinity ? null : { first, last };
}

// The host's cumulative port state at a moment: for every port, its newest
// observation from any scan up to then. This is what makes runs of
// different port ranges add up instead of contradicting each other - a
// scan of port 80 updates port 80 and leaves every other port as the last
// scan that asked about it saw it. The same reconstruction the server uses
// for current_host_ports, with the clock wound back.
function stateAt(history: HostPortObservation[], include: (row: HostPortObservation) => boolean): Map<string, HostPortObservation> {
  const state = new Map<string, HostPortObservation>();
  for (const row of history) {
    if (!include(row)) continue;
    const current = state.get(keyOf(row));
    if (!current || Date.parse(row.observed_at) > Date.parse(current.observed_at)) state.set(keyOf(row), row);
  }
  return state;
}

/** The cumulative state as of the end of a run, that run included. */
export function stateAfterRun(history: HostPortObservation[], jobId: string): Map<string, HostPortObservation> {
  const bounds = runBounds(history, jobId);
  if (!bounds) return new Map();
  return stateAt(history, (r) => r.scan_job_id === jobId || Date.parse(r.observed_at) <= bounds.last);
}

/** The cumulative state just before a run began, that run excluded. */
export function stateBeforeRun(history: HostPortObservation[], jobId: string): Map<string, HostPortObservation> {
  const bounds = runBounds(history, jobId);
  if (!bounds) return new Map();
  return stateAt(history, (r) => r.scan_job_id !== jobId && Date.parse(r.observed_at) < bounds.first);
}

function compareStates(beforeState: Map<string, HostPortObservation>, afterState: Map<string, HostPortObservation>): PortChange[] {
  const changes: PortChange[] = [];
  for (const key of new Set([...beforeState.keys(), ...afterState.keys()])) {
    const b = beforeState.get(key) ?? null;
    const a = afterState.get(key) ?? null;
    const [portStr, protocol] = key.split("/");
    const port = Number(portStr);

    // A port recorded as closed in one state and unknown in the other is
    // not a change worth reporting - both mean "not open".
    const bOpen = b?.state === "open";
    const aOpen = a?.state === "open";

    if (!bOpen && aOpen) {
      changes.push({ port, protocol, before: b, after: a, kind: "opened", details: [] });
      continue;
    }
    if (bOpen && !aOpen) {
      changes.push({ port, protocol, before: b, after: a, kind: "closed", details: [] });
      continue;
    }
    if (!bOpen && !aOpen) continue;

    const details: string[] = [];
    if ((b?.service_name ?? null) !== (a?.service_name ?? null)) {
      details.push(`service ${b?.service_name ?? "unknown"} → ${a?.service_name ?? "unknown"}`);
    }
    const beforeProduct = [b?.service_product, b?.service_version].filter(Boolean).join(" ");
    const afterProduct = [a?.service_product, a?.service_version].filter(Boolean).join(" ");
    if (beforeProduct !== afterProduct) {
      details.push(`version ${beforeProduct || "unknown"} → ${afterProduct || "unknown"}`);
    }
    changes.push({ port, protocol, before: b, after: a, kind: details.length > 0 ? "changed" : "unchanged", details });
  }
  // Opened first, then closed, then changed - the order they matter in.
  const rank = { opened: 0, closed: 1, changed: 2, unchanged: 3 };
  return changes.sort((x, y) => rank[x.kind] - rank[y.kind] || x.port - y.port);
}

/**
 * What one run changed: the host's cumulative state just before it against
 * the state after it. Only ports the run actually reported can differ -
 * everything else carries over unchanged - so a scan of a single port
 * never reports the host's other ports as closed.
 */
export function changesInRun(history: HostPortObservation[], jobId: string): PortChange[] {
  return compareStates(stateBeforeRun(history, jobId), stateAfterRun(history, jobId)).filter((c) => c.kind !== "unchanged");
}

export function diffScans(history: HostPortObservation[], beforeJobId: string, afterJobId: string): PortChange[] {
  return compareStates(stateAfterRun(history, beforeJobId), stateAfterRun(history, afterJobId));
}
