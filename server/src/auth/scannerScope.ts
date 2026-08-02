import type { Request } from "express";

// null = unrestricted (admin, or a user/operator with no assignment rows -
// see the user_scanner_agents migration). A non-null array is the
// exhaustive set of scanner_agent_id values this session may see data
// from, meant to be applied as a `.where(col, "in", allowed)` (or
// equivalent raw-SQL `= ANY(...)`) everywhere a fleet-wide query would
// otherwise return every scanner's data.
export function getAllowedScannerAgentIds(req: Request): string[] | null {
  return req.session.allowedScannerAgentIds ?? null;
}
