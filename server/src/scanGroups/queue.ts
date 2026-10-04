import type { Kysely, Transaction } from "kysely";
import type { Database } from "../db/types";
import { partRate, splitTargetSpec } from "../lib/scanSplit";
import { expandTargetPattern } from "../lib/targetPattern";

// Everything a queued scan carries apart from its target and scanner -
// identical for every part of a split scan.
export interface ScanRequestTemplate {
  port_spec: string;
  requested_by: string | null;
  nse_profile: "default" | "all_safe" | "custom";
  nse_scripts: string[] | null;
  nse_profile_label: string | null;
  nuclei_profile: "off" | "safe" | "custom";
  nuclei_tags: string[] | null;
  nuclei_profile_label: string | null;
  masscan_rate: number | null;
  priority: "high" | "normal" | "low";
  tags: string[] | null;
  schedule_id: string | null;
}

export interface QueuedPart {
  id: string;
  scannerAgentId: string;
  targetSpec: string;
  addresses: number | null;
  masscanRate: number | null;
  part: number | null;
}

export type QueueResult =
  | { ok: true; groupId: string | null; parts: QueuedPart[] }
  | { ok: false; error: string };

// Queues one scan on one or several scanners. The only place a scan
// request is created from a target, shared by the ad-hoc form and the
// scheduler, so the two cannot split a target differently.
//
// One scanner is exactly what this always did: a single scan_requests
// row with the target as typed and no group. Several split the target
// (lib/scanSplit.ts) into one row per scanner under a scan_groups row; a
// scanner whose share came out empty (a target smaller than the set) gets
// no row at all rather than a scan of nothing.
export async function queueScan(
  executor: Kysely<Database> | Transaction<Database>,
  targetSpec: string,
  scannerAgentIds: string[],
  template: ScanRequestTemplate,
  rateSplit: boolean
): Promise<QueueResult> {
  // A pattern ("10.46.*.125", "10.46.0.0/16 !*.2") becomes the plain
  // list the scanner runs before anything else happens, so the split,
  // the length limit and the scanner all only ever see ordinary targets.
  // The pattern itself is kept on the request (target_pattern) and on a
  // group, as what was actually asked for.
  const expansion = expandTargetPattern(targetSpec);
  if (!expansion.ok) return expansion;
  const plainSpec = expansion.expanded ? expansion.spec : targetSpec;
  const targetPattern = expansion.expanded ? targetSpec.trim() : null;

  const split = splitTargetSpec(plainSpec, scannerAgentIds);
  if (!split.ok) return split;

  if (split.parts.length === 1) {
    const only = split.parts[0];
    // Unchanged from before splitting existed: the target exactly as
    // given, even when several scanners were chosen and only one of them
    // ended up with anything to do.
    const row = await executor
      .insertInto("scan_requests")
      .values({
        ...template,
        scanner_agent_id: only.scannerAgentId,
        host_id: null,
        target_spec: scannerAgentIds.length === 1 ? plainSpec : only.targetSpec,
        target_pattern: targetPattern,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    return {
      ok: true,
      groupId: null,
      parts: [{ id: row.id, scannerAgentId: only.scannerAgentId, targetSpec: only.targetSpec, addresses: only.addresses, masscanRate: template.masscan_rate, part: null }],
    };
  }

  const n = split.parts.length;
  const group = await executor
    .insertInto("scan_groups")
    .values({
      target_spec: targetSpec,
      port_spec: template.port_spec,
      parts: n,
      scanner_agent_ids: split.parts.map((p) => p.scannerAgentId),
      masscan_rate_split: rateSplit,
      requested_by: template.requested_by,
      schedule_id: template.schedule_id,
    })
    .returning(["id"])
    .executeTakeFirstOrThrow();

  const parts: QueuedPart[] = [];
  for (const [i, p] of split.parts.entries()) {
    const masscanRate = partRate(template.masscan_rate, n, rateSplit);
    const row = await executor
      .insertInto("scan_requests")
      .values({
        ...template,
        masscan_rate: masscanRate,
        scanner_agent_id: p.scannerAgentId,
        host_id: null,
        target_spec: p.targetSpec,
        scan_group_id: group.id,
        group_part: i + 1,
        group_parts: n,
        target_pattern: targetPattern,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    parts.push({ id: row.id, scannerAgentId: p.scannerAgentId, targetSpec: p.targetSpec, addresses: p.addresses, masscanRate, part: i + 1 });
  }
  return { ok: true, groupId: group.id, parts };
}
