import type { PatchPriorityHost } from "../api";
import { lifecycleOf } from "./softwareLifecycle";
import { LONG_UPTIME_DAYS, uptimeDays } from "./uptime";

// Which hosts to patch first, ranked from signals the platform already
// has. The weights are a judgement, written down here so they can be
// argued with rather than buried in a query:
//
//   - a KEV-listed CVE (confirmed exploited in the wild)  100
//   - the worst CVSS score, x8 (a 9.8 is worth 78)         up to 80
//   - software past upstream end of life                   40 (ending soon: 10)
//   - up more than a year / more than LONG_UPTIME_DAYS     30 / 20
//   - a version older than the fleet's newest              15
//
// So exploitation outranks severity, severity outranks age, and a long
// uptime alone - no known CVE, nothing end of life - lands a device in
// the list without putting it above anything actually exposed. Every
// reason is reported beside the score, so the ranking explains itself.

export interface PriorityReason {
  kind: "kev" | "cvss" | "eol" | "eol_soon" | "uptime" | "behind_fleet";
  label: string;
  points: number;
}

export interface RankedHost extends PatchPriorityHost {
  score: number;
  reasons: PriorityReason[];
}

export function rankHost(host: PatchPriorityHost, now = new Date()): RankedHost {
  const reasons: PriorityReason[] = [];
  if (host.kevIds.length > 0) {
    reasons.push({ kind: "kev", label: `known exploited: ${host.kevIds.slice(0, 3).join(", ")}${host.kevIds.length > 3 ? " ..." : ""}`, points: 100 });
  }
  if (host.maxCvss !== null && host.cveCount > 0) {
    reasons.push({ kind: "cvss", label: `${host.cveCount} CVE${host.cveCount === 1 ? "" : "s"}, worst CVSS ${host.maxCvss.toFixed(1)}`, points: Math.round(host.maxCvss * 8) });
  }
  const eol = host.software.map((s) => ({ s, l: lifecycleOf(s.product, s.version, now) })).filter((x) => x.l);
  const ended = eol.filter((x) => x.l!.status === "ended");
  if (ended.length > 0) {
    reasons.push({ kind: "eol", label: `end of life: ${ended.map((x) => `${x.s.product} ${x.s.version}`).join(", ")}`, points: 40 });
  } else if (eol.length > 0) {
    reasons.push({ kind: "eol_soon", label: `end of life soon: ${eol.map((x) => `${x.s.product} ${x.s.version}`).join(", ")}`, points: 10 });
  }
  const days = uptimeDays(host.bootTime);
  if (days !== null && days >= LONG_UPTIME_DAYS) {
    reasons.push({ kind: "uptime", label: `up ${days} days`, points: days >= 365 ? 30 : 20 });
  }
  const behind = host.software.filter((s) => s.newerInFleet);
  if (behind.length > 0) {
    reasons.push({
      kind: "behind_fleet",
      label: `older than elsewhere: ${behind.map((s) => `${s.product} ${s.version} (${s.newerInFleet} exists)`).join(", ")}`,
      points: 15,
    });
  }
  return { ...host, score: reasons.reduce((n, r) => n + r.points, 0), reasons };
}

export function rankHosts(hosts: PatchPriorityHost[], now = new Date()): RankedHost[] {
  return hosts
    .map((h) => rankHost(h, now))
    .filter((h) => h.score > 0)
    .sort((a, b) => b.score - a.score || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}
