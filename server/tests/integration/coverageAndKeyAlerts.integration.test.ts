import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { sql } from "kysely";
import { db } from "../../src/db";
import { runOperationalAlertChecks } from "../../src/webhooks/operationalAlerts";
import { closeDb, createTestAgent, deleteTestAgent, type TestAgent } from "./helpers";

// Class E (240.0.0.0/4) - reserved, so nothing here collides with real
// data when the suite runs against a copy of a production database.
const TRACKED = "240.30.0.0/24";
const CLONE_A = "240.30.0.11";
const CLONE_B = "240.30.0.12";
const CLONE_C = "240.30.0.13";
const SHARED_FP = "SHA256:coverageKeyAlertsTest000000000000000000001";

// The two pages added in the previous round could only tell you something
// if somebody opened them - which for "nobody is scanning this range" is
// exactly the wrong mode, since a forgotten range is precisely what nobody
// thinks to go and look at. These drive the real periodic checker.
describe("network.coverage_stale and ssh_key.shared alerts", () => {
  let agent: TestAgent;
  let webhookId: string;
  let networkId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-covalert-agent");
    const row = await db
      .insertInto("webhooks")
      .values({
        name: `it-covalert-hook-${Date.now()}`,
        channel_type: "webhook",
        url: "http://127.0.0.1:9/never-listening",
        events: ["network.coverage_stale", "ssh_key.shared"],
        enabled: true,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    webhookId = row.id;

    const network = await db
      .insertInto("monitored_networks")
      .values({ label: "it-covalert-net", cidr: TRACKED, created_by: "it" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    networkId = network.id;
  });

  afterEach(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
  });

  afterAll(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await db.deleteFrom("monitored_networks").where("id", "=", networkId).execute();
    await db.deleteFrom("ssh_shared_key_alerts").where("fingerprint_sha256", "=", SHARED_FP).execute();
    await sql`DELETE FROM scan_jobs WHERE target_spec = ${TRACKED}`.execute(db);
    await sql`DELETE FROM hosts WHERE ip <<= ${TRACKED}::cidr`.execute(db);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function deliveredEvents(): Promise<string[]> {
    const rows = await db.selectFrom("webhook_deliveries").select(["event"]).where("webhook_id", "=", webhookId).execute();
    return rows.map((r) => r.event);
  }

  // dispatchWebhook deliberately doesn't await the delivery (see
  // dispatch.ts), so the row lands shortly after the check returns.
  async function waitForDelivery(event: string, timeoutMs = 3000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if ((await deliveredEvents()).includes(event)) return true;
      await new Promise((r) => setTimeout(r, 50));
    }
    return false;
  }

  async function confirmNoDelivery(event: string, settleMs = 750): Promise<boolean> {
    await new Promise((r) => setTimeout(r, settleMs));
    return !(await deliveredEvents()).includes(event);
  }

  async function networkRow() {
    return db
      .selectFrom("monitored_networks")
      .select(["coverage_alert_sent_at"])
      .where("id", "=", networkId)
      .executeTakeFirstOrThrow();
  }

  async function addHostWithKey(ip: string, fingerprint: string): Promise<void> {
    const host = await db
      .insertInto("hosts")
      .values({ ip, scanner_agent_id: agent.id })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: TRACKED, port_spec: "22", status: "completed" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    await db
      .insertInto("ssh_host_keys")
      .values({
        host_id: host.id,
        scan_job_id: job.id,
        port: 22,
        key_type: "ssh-rsa",
        bits: 3072,
        fingerprint_sha256: fingerprint,
      })
      .execute();
  }

  it("alerts on a tracked range nothing has scanned, once", async () => {
    await runOperationalAlertChecks();
    expect(await waitForDelivery("network.coverage_stale")).toBe(true);
    expect((await networkRow()).coverage_alert_sent_at).not.toBeNull();

    // Unchanged condition: a second pass must stay silent, or a forgotten
    // range would alert every five minutes forever.
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await runOperationalAlertChecks();
    expect(await confirmNoDelivery("network.coverage_stale")).toBe(true);
  });

  it("clears the flag once the range is scanned again, so the next gap alerts", async () => {
    await db
      .insertInto("scan_jobs")
      .values({
        scanner_agent_id: agent.id,
        target_spec: TRACKED,
        port_spec: "80",
        status: "completed",
        started_at: new Date().toISOString(),
      })
      .execute();

    await runOperationalAlertChecks();
    expect((await networkRow()).coverage_alert_sent_at).toBeNull();
    expect(await confirmNoDelivery("network.coverage_stale")).toBe(true);
  });

  it("alerts when one host key turns up on two addresses, and again when a third appears", async () => {
    await addHostWithKey(CLONE_A, SHARED_FP);
    // One address is not a finding.
    await runOperationalAlertChecks();
    expect(await confirmNoDelivery("ssh_key.shared")).toBe(true);

    await addHostWithKey(CLONE_B, SHARED_FP);
    await runOperationalAlertChecks();
    expect(await waitForDelivery("ssh_key.shared")).toBe(true);

    // Unchanged group: silent.
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await runOperationalAlertChecks();
    expect(await confirmNoDelivery("ssh_key.shared")).toBe(true);

    // A third machine with the same key is news even though the group was
    // already reported - this is what storing ip_count buys.
    await addHostWithKey(CLONE_C, SHARED_FP);
    await runOperationalAlertChecks();
    expect(await waitForDelivery("ssh_key.shared")).toBe(true);

    const stored = await db
      .selectFrom("ssh_shared_key_alerts")
      .select(["ip_count"])
      .where("fingerprint_sha256", "=", SHARED_FP)
      .executeTakeFirstOrThrow();
    expect(stored.ip_count).toBe(3);
  });

  it("forgets a group that stops being shared", async () => {
    await sql`DELETE FROM hosts WHERE ip = ${CLONE_B}::inet OR ip = ${CLONE_C}::inet`.execute(db);
    await runOperationalAlertChecks();

    const stored = await db
      .selectFrom("ssh_shared_key_alerts")
      .select(["fingerprint_sha256"])
      .where("fingerprint_sha256", "=", SHARED_FP)
      .executeTakeFirst();
    // Forgotten, so the same key reappearing on two machines later is
    // reported as new rather than silently swallowed.
    expect(stored).toBeUndefined();
  });
});
