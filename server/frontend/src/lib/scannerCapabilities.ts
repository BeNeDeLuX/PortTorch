import { ScannerAgent } from "../api";
import { compareSemver } from "./semver";

// Which scanner version a given webserver feature actually needs on the
// other side. The webserver and scanner are versioned and deployed
// independently (see the root CLAUDE.md), so a dashboard control can
// exist for something the target scanner is simply too old to act on.
//
// This matters because the failure mode is *silent*, not loud: the
// webserver stores the setting and returns it on claim, and an older
// scanner just doesn't decode the field - the scan runs with the
// scanner's own configured value instead, with no error anywhere. For a
// setting whose whole purpose is "probe this fragile segment gently",
// silently not applying it is the worst possible outcome, so the form
// says so up front rather than letting someone believe it took effect.
export const MIN_SCANNER_VERSION = {
  // scanner_requests.masscan_rate, wired through client.go/server.go in
  // scanner 0.9.2 - anything older ignores the field entirely.
  scanRate: "0.9.2",
} as const;

export type ScannerCapability = keyof typeof MIN_SCANNER_VERSION;

export type CapabilitySupport = "supported" | "too-old" | "unknown";

/**
 * Whether `agent` is new enough for `capability`.
 *
 * "unknown" is a genuinely distinct answer from "too-old": scanner_agents
 * .version is only populated once that scanner has made at least one
 * authenticated request, so a freshly created agent that has never polled
 * has no version to compare - treating that as too-old would put a
 * warning on every new agent, and treating it as supported would hide a
 * real problem. Callers phrase the two cases differently.
 */
export function capabilitySupport(agent: ScannerAgent | undefined, capability: ScannerCapability): CapabilitySupport {
  if (!agent || !agent.version) return "unknown";
  return compareSemver(agent.version, MIN_SCANNER_VERSION[capability]) >= 0 ? "supported" : "too-old";
}
