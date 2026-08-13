import { db } from "../db";

// A scan-profile pick, as sent by the frontend when triggering a rescan
// or creating/editing a schedule.
export type NSEProfileSelection =
  | { kind: "default" }
  | { kind: "all_safe" }
  | { kind: "custom"; profileId: string };

export class ScanProfileNotFoundError extends Error {
  constructor() {
    super("scan profile not found");
  }
}

// Turns a selection into the three snapshot columns scan_requests/
// scan_schedules actually store. "default"/"all_safe" never touch the
// database - the canonical script lists for those two live only in the
// Go scanner (see nse_default_scripts.go/nse_safe_scripts.go), so the
// webserver never needs to know their contents, only the symbolic kind.
// "custom" resolves the named profile's current script list into a
// SNAPSHOT, copied once at call time - a later edit/delete of that
// scan_profiles row can never retroactively change what's already been
// captured here (see the scan_profiles migration's own comment).
export async function resolveNSEProfile(
  selection: NSEProfileSelection
): Promise<{ nseProfile: "default" | "all_safe" | "custom"; nseScripts: string[] | null; nseProfileLabel: string }> {
  if (selection.kind === "default") {
    return { nseProfile: "default", nseScripts: null, nseProfileLabel: "Default" };
  }
  if (selection.kind === "all_safe") {
    return { nseProfile: "all_safe", nseScripts: null, nseProfileLabel: "All Safe Modules" };
  }
  const profile = await db
    .selectFrom("scan_profiles")
    .select(["name", "nse_scripts"])
    .where("id", "=", selection.profileId)
    .executeTakeFirst();
  if (!profile) throw new ScanProfileNotFoundError();
  return { nseProfile: "custom", nseScripts: profile.nse_scripts, nseProfileLabel: profile.name };
}
