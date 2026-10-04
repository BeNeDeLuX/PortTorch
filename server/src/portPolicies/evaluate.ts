import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { parsePortSpec, portSpecCovers } from "../lib/portSpec";
import { dispatchWebhook } from "../webhooks/dispatch";

const CHECK_INTERVAL_MS = 5 * 60 * 1000;
// A policy over a /8 that is wrong in the "allow" direction could match
// every open port in it; the page and the alert both say when it was cut.
export const VIOLATION_LIMIT = 1000;

export interface PolicyRow {
  id: string;
  network: string;
  scanner_agent_id: string | null;
  mode: "allow" | "deny";
  ports: string;
}

export interface Violation {
  hostId: string;
  ip: string;
  hostname: string | null;
  scannerAgentName: string | null;
  port: number;
  protocol: string;
  serviceName: string | null;
  serviceProduct: string | null;
  observedAt: Date;
}

// A violation is an open port, in the policy's network and scope, that the
// policy does not permit: outside the list for "allow", inside it for
// "deny". Read from current_host_ports - the newest observation per port -
// so a port a scan recorded closed stops violating, and one that silently
// stopped answering keeps violating until a scan says otherwise, exactly
// as the rest of the dashboard treats it.
export async function policyViolations(
  policy: PolicyRow,
  allowed: string[] | null
): Promise<{ items: Violation[]; truncated: boolean }> {
  const spec = parsePortSpec(policy.ports);
  // Validated on save, so this only happens to a row edited by hand. No
  // spec means no claim either way.
  if (!spec) return { items: [], truncated: false };

  const conditions = [sql`h.ip <<= ${policy.network}::cidr`, sql`chp.state = 'open'`];
  if (policy.scanner_agent_id) conditions.push(sql`h.scanner_agent_id = ${policy.scanner_agent_id}::uuid`);
  if (allowed) conditions.push(sql`h.scanner_agent_id = ANY(${allowed}::uuid[])`);

  const { rows } = await sql<{
    host_id: string;
    ip: string;
    hostname: string | null;
    scanner_agent_name: string | null;
    port: number;
    protocol: string;
    service_name: string | null;
    service_product: string | null;
    observed_at: Date;
  }>`
    SELECT h.id AS host_id, host(h.ip) AS ip, h.hostname, sa.name AS scanner_agent_name,
           chp.port, chp.protocol, chp.service_name, chp.service_product, chp.observed_at
    FROM current_host_ports chp
    JOIN hosts h ON h.id = chp.host_id
    LEFT JOIN scanner_agents sa ON sa.id = h.scanner_agent_id
    WHERE ${sql.join(conditions, sql` AND `)}
    ORDER BY h.ip, chp.port, chp.protocol
  `.execute(db);

  const items: Violation[] = [];
  for (const r of rows) {
    const covered = portSpecCovers(spec, Number(r.port), r.protocol);
    if (policy.mode === "allow" ? covered : !covered) continue;
    if (items.length === VIOLATION_LIMIT) return { items, truncated: true };
    items.push({
      hostId: r.host_id,
      ip: r.ip,
      hostname: r.hostname,
      scannerAgentName: r.scanner_agent_name,
      port: Number(r.port),
      protocol: r.protocol,
      serviceName: r.service_name,
      serviceProduct: r.service_product,
      observedAt: r.observed_at,
    });
  }
  return { items, truncated: false };
}

export const violationKey = (v: Pick<Violation, "hostId" | "port" | "protocol">) => `${v.hostId}:${v.port}/${v.protocol}`;

// Alerts on violations the previous check had not reported, and forgets
// ones that went away so they alert again if they come back - the same
// bookkeeping as baseline.deviation.
export async function checkPortPolicies(): Promise<number> {
  const policies = await db
    .selectFrom("port_policies as p")
    .leftJoin("scanner_agents as sa", "sa.id", "p.scanner_agent_id")
    .select([
      "p.id",
      "p.name",
      sql<string>`p.network::text`.as("network"),
      "p.scanner_agent_id",
      "p.mode",
      "p.ports",
      "p.alerted_keys",
      "sa.name as scanner_agent_name",
    ])
    .where("p.enabled", "=", true)
    .execute();

  let alerted = 0;
  for (const p of policies) {
    // null: an alert is not sent on any particular user's behalf.
    const { items } = await policyViolations(p, null);
    const keys = items.map(violationKey);
    const previous = new Set(p.alerted_keys);
    const fresh = items.filter((v) => !previous.has(violationKey(v)));

    if (fresh.length > 0) {
      const rule = p.mode === "allow" ? `only ${p.ports} allowed` : `${p.ports} not allowed`;
      const lines = fresh.slice(0, 20).map((v) => `${v.ip} ${v.port}/${v.protocol}${v.serviceName ? ` (${v.serviceName})` : ""}`);
      const more = fresh.length - lines.length;
      const message =
        `Port policy "${p.name}" (${p.network}, ${rule}) is violated: ` + lines.join("; ") + (more > 0 ? `; and ${more} more` : "");
      await dispatchWebhook(
        "port_policy.violation",
        message,
        {
          policy_id: p.id,
          policy_name: p.name,
          network: p.network,
          scanner_agent_name: p.scanner_agent_name,
          mode: p.mode,
          ports: p.ports,
          violations: fresh.map((v) => ({ ip: v.ip, hostname: v.hostname, port: v.port, protocol: v.protocol, service: v.serviceName })),
        },
        { scannerAgentId: p.scanner_agent_id }
      );
      alerted++;
    }

    const sameSet = keys.length === previous.size && keys.every((k) => previous.has(k));
    if (!sameSet) {
      await db.updateTable("port_policies").set({ alerted_keys: keys }).where("id", "=", p.id).execute();
    }
  }
  return alerted;
}

export function startPortPolicyChecks(): void {
  setInterval(() => {
    checkPortPolicies().catch((err) =>
      logger.error({ event: "port_policy_check.tick_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}
