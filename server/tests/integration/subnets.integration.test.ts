import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { sql } from "kysely";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  getApp,
  loginAs,
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

const CPE = "cpe:/a:it-subnets:widget:2.0";
const FP_CVE = "CVE-1999-9611";
const OPEN_CVE = "CVE-1999-9612";

interface Subnet {
  subnet: string;
  hosts: number;
  openPorts: number;
  hostsWithCves: number;
  criticalHosts: number;
  kevHosts: number;
  maxCvss: number | null;
  newHosts: number;
}

// "Which network is the problem?" - hosts grouped by the subnet their
// address falls in, with the host list's own risk policy applied.
describe("GET /api/subnets", () => {
  let agent: TestAgent;
  let otherAgent: TestAgent;
  let operator: TestUser;
  let restricted: TestUser;
  let op: SessionClient;
  let scoped: SessionClient;

  async function ingest(a: TestAgent, ip: string, ports: object[]) {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${a.apiKey}`)
      .send({ targetSpec: ip, portSpec: "22,443" });
    const res = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${a.apiKey}`)
      .send({ scanJobId: job.body.id, hosts: [{ ip, ports }] });
    expect(res.status).toBe(204);
  }

  beforeAll(async () => {
    agent = await createTestAgent("it-subnets");
    otherAgent = await createTestAgent("it-subnets-other");
    operator = await createTestUser("operator");
    restricted = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: agent.id }).execute();
    op = await loginAs(operator.username, operator.password);
    scoped = await loginAs(restricted.username, restricted.password);

    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE,
        cves: JSON.stringify([
          { id: FP_CVE, cvssScore: 9.8, cvssSeverity: "CRITICAL", description: "dismissed" },
          { id: OPEN_CVE, cvssScore: 7.5, cvssSeverity: "HIGH", description: "still open" },
        ]),
      })
      .onConflict((oc) => oc.column("cpe").doUpdateSet({ cves: (eb) => eb.ref("excluded.cves") }))
      .execute();
    await db
      .insertInto("kev_cache")
      .values({ cve_id: FP_CVE, date_added: "1999-01-01", known_ransomware_campaign_use: "Unknown" })
      .onConflict((oc) => oc.column("cve_id").doNothing())
      .execute();

    await ingest(agent, "240.61.1.10", [{ port: 443, protocol: "tcp", state: "open", serviceName: "https", cpes: [CPE] }]);
    await ingest(agent, "240.61.1.11", [
      { port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
      { port: 443, protocol: "tcp", state: "open", serviceName: "https" },
    ]);
    await ingest(agent, "240.61.2.5", [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }]);
    await ingest(agent, "240.61.3.1", [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }]);
    await ingest(agent, "2001:db8:61::1", [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }]);
    await ingest(otherAgent, "240.61.4.1", [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }]);

    await db.updateTable("hosts").set({ retired_at: new Date() }).where("ip", "=", "240.61.3.1").execute();

    // The 9.8 is a KEV and would make the subnet critical and exploited
    // if triage were ignored - it has been dismissed as a false positive.
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", "240.61.1.10").executeTakeFirstOrThrow();
    const triage = await op.put("/api/finding-triage").send({ kind: "cve", hostId: host.id, cveId: FP_CVE, state: "false_positive" });
    expect(triage.status).toBeLessThan(300);
  });

  afterAll(async () => {
    await sql`DELETE FROM hosts WHERE ip <<= '240.61.0.0/16'::cidr OR ip = '2001:db8:61::1'::inet`.execute(db);
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agent.id, otherAgent.id]).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "=", FP_CVE).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(otherAgent.id);
    await deleteTestUser(operator.id);
    await deleteTestUser(restricted.id);
    await closeDb();
  });

  async function mine(client: SessionClient, query = ""): Promise<Map<string, Subnet>> {
    const res = await client.get(`/api/subnets${query}`);
    expect(res.status).toBe(200);
    const out = new Map<string, Subnet>();
    for (const s of res.body.subnets as Subnet[]) {
      if (s.subnet.startsWith("240.61.") || s.subnet.startsWith("2001:db8:61:")) out.set(s.subnet, s);
    }
    return out;
  }

  it("groups hosts per /24, with IPv6 per /64, and counts real numbers", async () => {
    const subnets = await mine(op);
    expect([...subnets.keys()].sort()).toEqual([
      "2001:db8:61::/64",
      "240.61.1.0/24",
      "240.61.2.0/24",
      "240.61.3.0/24",
      "240.61.4.0/24",
    ]);
    const a = subnets.get("240.61.1.0/24")!;
    expect(a.hosts).toBe(2);
    // Numbers, not the bigint strings node-postgres would hand back.
    expect(a.openPorts).toBe(3);
    expect(typeof a.openPorts).toBe("number");
  });

  it("applies the host list's triage policy to the risk", async () => {
    const a = (await mine(op)).get("240.61.1.0/24")!;
    // Only the untriaged 7.5 counts: the dismissed 9.8 KEV neither makes
    // the subnet critical nor exploited.
    expect(a.hostsWithCves).toBe(1);
    expect(a.maxCvss).toBe(7.5);
    expect(a.criticalHosts).toBe(0);
    expect(a.kevHosts).toBe(0);
    expect((await mine(op)).get("240.61.2.0/24")!.hostsWithCves).toBe(0);
  });

  it("widens the grouping on request and falls back from an unknown prefix", async () => {
    const wide = await mine(op, "?prefix=16");
    expect(wide.get("240.61.0.0/16")!.hosts).toBe(5);
    // IPv6 stays per /64 whatever the IPv4 grouping.
    expect(wide.has("2001:db8:61::/64")).toBe(true);

    const res = await op.get("/api/subnets?prefix=13");
    expect(res.body.prefix).toBe(24);
  });

  it("hides retired hosts only when asked, and narrows by scanner", async () => {
    expect((await mine(op)).has("240.61.3.0/24")).toBe(true);
    expect((await mine(op, "?hideRetired=1")).has("240.61.3.0/24")).toBe(false);

    const narrowed = await mine(op, `?scannerAgentId=${otherAgent.id}`);
    expect([...narrowed.keys()]).toEqual(["240.61.4.0/24"]);
    // A malformed id is ignored rather than turned into a 500.
    expect((await op.get("/api/subnets?scannerAgentId=not-a-uuid")).status).toBe(200);
  });

  it("counts hosts first seen within the requested window, and only allowed windows", async () => {
    // Everything in 240.61.1.0/24 was created just now; age one of them.
    await sql`UPDATE hosts SET first_seen_at = now() - interval '10 days' WHERE ip = (
      SELECT ip FROM hosts WHERE ip <<= '240.61.1.0/24'::cidr ORDER BY ip LIMIT 1)`.execute(db);
    const week = (await mine(op, "?newDays=7")).get("240.61.1.0/24")!;
    expect(week.newHosts).toBe(1);
    const month = await op.get("/api/subnets?newDays=30");
    expect(month.body.newDays).toBe(30);
    expect(month.body.subnets.find((s: Subnet) => s.subnet === "240.61.1.0/24").newHosts).toBe(2);
    // An arbitrary window falls back to the default rather than running.
    expect((await op.get("/api/subnets?newDays=4000")).body.newDays).toBe(7);
  });

  it("never shows a restricted user a scanner outside their scope", async () => {
    const subnets = await mine(scoped);
    expect(subnets.has("240.61.4.0/24")).toBe(false);
    expect(subnets.has("240.61.1.0/24")).toBe(true);
    // Asking for the out-of-scope scanner explicitly narrows to nothing,
    // never widens.
    expect((await mine(scoped, `?scannerAgentId=${otherAgent.id}`)).size).toBe(0);
  });
});
