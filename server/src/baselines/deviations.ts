import { db } from "../db";
import { logger } from "../logger";
import { computeNetworkChanges, type NetworkChanges } from "../subnets/changes";
import { dispatchWebhook } from "../webhooks/dispatch";

const CHECK_INTERVAL_MS = 5 * 60 * 1000;

export interface BaselineRow {
  id: string;
  network: string;
  scanner_agent_id: string | null;
  approved_at: Date;
}

// Deviations from a baseline are exactly the Changes view's comparison
// from the approval moment to now - one computation, so the page, the
// list and the alert cannot disagree about what changed.
export function baselineDeviations(baseline: BaselineRow, allowed: string[] | null): Promise<NetworkChanges> {
  return computeNetworkChanges({
    network: baseline.network,
    from: new Date(baseline.approved_at),
    to: new Date(),
    allowed,
    filterIds: baseline.scanner_agent_id ? [baseline.scanner_agent_id] : [],
    hideRetired: false,
  });
}

// One key per deviation that can alert. Hosts not seen since the approval
// are deliberately not among them: "not seen" also means "not scanned",
// and alerting on every host of a range nobody swept this week would make
// the alert useless in exactly the weeks it matters. They are shown on
// the page, with the number of scans beside them.
export function deviationKeys(changes: NetworkChanges): string[] {
  return [
    ...changes.newHosts.items.map((h) => `host:${h.hostId}`),
    ...changes.openedPorts.items.map((p) => `open:${p.hostId}:${p.port}/${p.protocol}`),
    ...changes.closedPorts.items.map((p) => `closed:${p.hostId}:${p.port}/${p.protocol}`),
  ];
}

function describe(changes: NetworkChanges, fresh: Set<string>): string[] {
  const lines: string[] = [];
  for (const h of changes.newHosts.items) {
    if (fresh.has(`host:${h.hostId}`)) lines.push(`new host ${h.ip}${h.openPorts.length ? ` (${h.openPorts.join(", ")})` : ""}`);
  }
  for (const p of changes.openedPorts.items) {
    if (fresh.has(`open:${p.hostId}:${p.port}/${p.protocol}`)) lines.push(`${p.ip} opened ${p.port}/${p.protocol}`);
  }
  for (const p of changes.closedPorts.items) {
    if (fresh.has(`closed:${p.hostId}:${p.port}/${p.protocol}`)) lines.push(`${p.ip} closed ${p.port}/${p.protocol}`);
  }
  return lines;
}

// Alerts on deviations the previous check had not already reported. The
// stored set is replaced by the current one each time, so a deviation that
// disappears (a port closing again) is forgotten and alerts afresh if it
// returns - the same come-and-go idea as scanner.offline.
export async function checkBaselines(): Promise<number> {
  const baselines = await db
    .selectFrom("network_baselines as b")
    .leftJoin("scanner_agents as sa", "sa.id", "b.scanner_agent_id")
    .select(["b.id", "b.network", "b.scanner_agent_id", "b.approved_at", "b.alerted_keys", "b.note", "sa.name as scanner_agent_name"])
    .execute();

  let alerted = 0;
  for (const b of baselines) {
    // null: an alert is not sent on any particular user's behalf.
    const changes = await baselineDeviations(b, null);
    const keys = deviationKeys(changes);
    const previous = new Set(b.alerted_keys);
    const fresh = new Set(keys.filter((k) => !previous.has(k)));

    if (fresh.size > 0) {
      const lines = describe(changes, fresh);
      const shown = lines.slice(0, 20);
      const more = lines.length - shown.length;
      const scope = b.scanner_agent_name ? ` (scanner "${b.scanner_agent_name}")` : "";
      const message =
        `${changes.network}${scope} deviates from the baseline approved ${new Date(b.approved_at).toISOString()}: ` +
        shown.join("; ") +
        (more > 0 ? `; and ${more} more` : "");
      await dispatchWebhook(
        "baseline.deviation",
        message,
        {
          baseline_id: b.id,
          network: changes.network,
          scanner_agent_name: b.scanner_agent_name,
          note: b.note,
          approved_at: b.approved_at,
          new_hosts: changes.newHosts.items.filter((h) => fresh.has(`host:${h.hostId}`)).map((h) => ({ ip: h.ip, open_ports: h.openPorts })),
          opened_ports: changes.openedPorts.items
            .filter((p) => fresh.has(`open:${p.hostId}:${p.port}/${p.protocol}`))
            .map((p) => ({ ip: p.ip, port: p.port, protocol: p.protocol, service: p.serviceName })),
          closed_ports: changes.closedPorts.items
            .filter((p) => fresh.has(`closed:${p.hostId}:${p.port}/${p.protocol}`))
            .map((p) => ({ ip: p.ip, port: p.port, protocol: p.protocol, service: p.serviceName })),
        },
        { scannerAgentId: b.scanner_agent_id }
      );
      alerted++;
    }

    const sameSet = keys.length === previous.size && keys.every((k) => previous.has(k));
    if (!sameSet) {
      await db.updateTable("network_baselines").set({ alerted_keys: keys }).where("id", "=", b.id).execute();
    }
  }
  return alerted;
}

export function startBaselineChecks(): void {
  setInterval(() => {
    checkBaselines().catch((err) =>
      logger.error({ event: "baseline_check.tick_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}
