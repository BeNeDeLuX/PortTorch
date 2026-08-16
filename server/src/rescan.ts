import { db } from "./db";
import { NSEProfileSelection, ScanProfileNotFoundError, resolveNSEProfile } from "./scanProfiles/resolve";

export type RescanOutcome =
  | { ok: true; request: { id: string; status: string; created_at: Date | string; nse_profile_label: string | null } }
  | { ok: false; status: number; error: string };

// Shared by the dashboard's rescan button (search/routes.ts) and the
// external API's rescan trigger (integrations/routes.ts) - both need the
// exact same "infer port spec from currently known open ports, use
// whichever scanner last scanned this host" logic, so it lives in one
// place rather than risking the two callers drifting apart.
//
// profile defaults to Default so the External API's rescan endpoint
// (which never sends one - a scan-profile picker was never asked for
// there) keeps behaving exactly as before this feature existed.
export async function requestRescan(
  hostId: string,
  requestedBy: string | null,
  profile: NSEProfileSelection = { kind: "default" }
): Promise<RescanOutcome> {
  const host = await db.selectFrom("hosts").select(["id", "ip"]).where("id", "=", hostId).executeTakeFirst();
  if (!host) {
    return { ok: false, status: 404, error: "host not found" };
  }

  const openPorts = await db
    .selectFrom("current_host_ports")
    .select(["port"])
    .distinct()
    .where("host_id", "=", hostId)
    .where("state", "=", "open")
    .orderBy("port")
    .execute();
  if (openPorts.length === 0) {
    return { ok: false, status: 400, error: "no known open ports to rescan for this host" };
  }
  const portSpec = openPorts.map((p) => p.port).join(",");

  const lastScan = await db
    .selectFrom("host_port_observations")
    .innerJoin("scan_jobs", "scan_jobs.id", "host_port_observations.scan_job_id")
    .select(["scan_jobs.scanner_agent_id"])
    .where("host_port_observations.host_id", "=", hostId)
    .orderBy("host_port_observations.observed_at", "desc")
    .executeTakeFirst();
  if (!lastScan) {
    return { ok: false, status: 400, error: "no scanner history found for this host" };
  }
  if (!lastScan.scanner_agent_id) {
    // The scanner that last scanned this host has since been deleted
    // (scan_jobs.scanner_agent_id is preserved as NULL rather than
    // deleting the historical job - see the scanner_agent_delete
    // migration). A scan_request with no scanner_agent_id would never be
    // polled by anyone, so fail clearly instead of creating a dead entry.
    return { ok: false, status: 400, error: "the scanner that last scanned this host no longer exists" };
  }

  let resolvedProfile;
  try {
    resolvedProfile = await resolveNSEProfile(profile);
  } catch (err) {
    if (err instanceof ScanProfileNotFoundError) {
      return { ok: false, status: 400, error: err.message };
    }
    throw err;
  }

  const request = await db
    .insertInto("scan_requests")
    .values({
      scanner_agent_id: lastScan.scanner_agent_id,
      host_id: host.id,
      target_spec: host.ip,
      port_spec: portSpec,
      requested_by: requestedBy,
      nse_profile: resolvedProfile.nseProfile,
      nse_scripts: resolvedProfile.nseScripts,
      nse_profile_label: resolvedProfile.nseProfileLabel,
    })
    .returning(["id", "status", "created_at", "nse_profile_label"])
    .executeTakeFirstOrThrow();

  return { ok: true, request };
}
