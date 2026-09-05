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
      continue;
    }
    byJob.set(row.scan_job_id, {
      scanJobId: row.scan_job_id,
      observedAt: row.observed_at,
      scannerAgentName: row.scanner_agent_name ?? null,
      portCount: 1,
    });
  }
  return [...byJob.values()].sort((a, b) => new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime());
}

function keyOf(row: HostPortObservation): string {
  return `${row.port}/${row.protocol}`;
}

/**
 * The port-level difference between two scan runs of one host.
 *
 * "Opened" and "closed" are relative to what each scan *recorded*, which
 * is not the same as what was true - masscan only ever reports ports it
 * sees open, so a port absent from a scan was either closed or simply not
 * covered by that scan's port spec. The caller shows both scans' port
 * specs alongside for exactly that reason; this cannot tell them apart
 * and does not pretend to.
 */
export function diffScans(
  history: HostPortObservation[],
  beforeJobId: string,
  afterJobId: string
): PortChange[] {
  const before = new Map<string, HostPortObservation>();
  const after = new Map<string, HostPortObservation>();
  for (const row of history) {
    if (row.scan_job_id === beforeJobId) before.set(keyOf(row), row);
    if (row.scan_job_id === afterJobId) after.set(keyOf(row), row);
  }

  const changes: PortChange[] = [];
  for (const key of new Set([...before.keys(), ...after.keys()])) {
    const b = before.get(key) ?? null;
    const a = after.get(key) ?? null;
    const [portStr, protocol] = key.split("/");
    const port = Number(portStr);

    // A port recorded as closed in one scan and absent from the other is
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
    changes.push({
      port,
      protocol,
      before: b,
      after: a,
      kind: details.length > 0 ? "changed" : "unchanged",
      details,
    });
  }

  // Opened first, then closed, then changed - the order they matter in.
  const rank = { opened: 0, closed: 1, changed: 2, unchanged: 3 };
  return changes.sort((x, y) => rank[x.kind] - rank[y.kind] || x.port - y.port);
}
