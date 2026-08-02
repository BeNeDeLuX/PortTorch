// baseSeverity is present for CVSS v3.x, but CVSS v2-only entries may only
// have a numeric score - fall back to deriving a severity band from that.
// Accepts either the per-host CveEntry (camelCase) or the fleet-wide
// FleetVulnerability shape (snake_case) - callers pass whichever fields
// they have.
export function cveSeverityClass(entry: {
  cvssScore?: number | null;
  cvssSeverity?: string | null;
}): "critical" | "high" | "medium" | "low" {
  const severity = entry.cvssSeverity?.toUpperCase();
  if (severity === "CRITICAL") return "critical";
  if (severity === "HIGH") return "high";
  if (severity === "MEDIUM") return "medium";
  if (severity === "LOW") return "low";

  const score = entry.cvssScore ?? 0;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}
