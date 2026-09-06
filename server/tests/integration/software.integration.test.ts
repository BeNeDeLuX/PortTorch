import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
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

// 240.0.0.0/4 is reserved and never routable - same reasoning as the
// other suites' fixtures, so this can never collide with real data.
const HOST_A = "240.13.0.1";
const HOST_B = "240.13.0.2";
const HOST_C = "240.13.0.3";
const CLOSED_HOST = "240.13.0.4";

const CPE = "cpe:/a:example:testproduct:1.2.3";
const FP_CVE = "CVE-2099-7001";
const ACCEPTED_CVE = "CVE-2099-7002";
const OPEN_CVE = "CVE-2099-7003";

interface SoftwareRow {
  product: string;
  version: string | null;
  sources: string[];
  hosts: number;
  ports: number;
  scanners: string[];
  cveCount: number;
  maxCvssScore: number | null;
  hasKev: boolean;
}

describe("software inventory", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-software-agent");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);

    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.13.0.0/24", portSpec: "80,443,8080" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [
          {
            ip: HOST_A,
            ports: [
              // Same product+version on two ports of one host: two ports,
              // one host.
              { port: 80, protocol: "tcp", state: "open", serviceName: "http", serviceProduct: "TestServer", serviceVersion: "1.2.3", cpes: [CPE] },
              { port: 443, protocol: "tcp", state: "open", serviceName: "https", serviceProduct: "TestServer", serviceVersion: "1.2.3", cpes: [CPE] },
            ],
          },
          {
            ip: HOST_B,
            ports: [
              { port: 80, protocol: "tcp", state: "open", serviceName: "http", serviceProduct: "TestServer", serviceVersion: "1.2.3", cpes: [CPE] },
              // A second version of the same product - its own row.
              { port: 8080, protocol: "tcp", state: "open", serviceName: "http", serviceProduct: "TestServer", serviceVersion: "2.0.0" },
            ],
          },
          {
            ip: HOST_C,
            ports: [
              // No version at all, and an empty-string version: both mean
              // "undetermined" and must collapse into one row.
              { port: 80, protocol: "tcp", state: "open", serviceName: "http", serviceProduct: "TestServer" },
              { port: 443, protocol: "tcp", state: "open", serviceName: "https", serviceProduct: "TestServer", serviceVersion: "" },
            ],
          },
          {
            ip: CLOSED_HOST,
            ports: [
              { port: 80, protocol: "tcp", state: "closed", serviceName: "http", serviceProduct: "ClosedOnlyProduct", serviceVersion: "9.9.9" },
            ],
          },
        ],
      });

    const hostRows = await db
      .selectFrom("hosts")
      .select(["id", "ip"])
      .where("scanner_agent_id", "=", agent.id)
      .execute();
    const hostIdByIp = new Map(hostRows.map((h) => [String(h.ip), h.id]));

    await db
      .insertInto("screenshots")
      .values([
        {
          host_id: hostIdByIp.get(HOST_A)!,
          scan_job_id: job.body.id,
          port: 443,
          url: `https://${HOST_A}/`,
          image_path: "it-software-a.png",
          page_title: "Grafana",
          // "TestServer:1.2.3" is the same thing nmap reported as a
          // product and a version, so the two must merge into one row.
          technologies: ["TestServer:1.2.3", "Forgejo", "jQuery:3.7.1"],
          captured_at: new Date().toISOString(),
        },
        {
          // An older capture of the same (host, port): must not be
          // counted alongside the newer one above.
          host_id: hostIdByIp.get(HOST_A)!,
          scan_job_id: job.body.id,
          port: 443,
          url: `https://${HOST_A}/`,
          image_path: "it-software-a-old.png",
          page_title: "Something Ancient",
          technologies: ["AncientTech"],
          captured_at: new Date(Date.now() - 86_400_000).toISOString(),
        },
        {
          host_id: hostIdByIp.get(HOST_B)!,
          scan_job_id: job.body.id,
          port: 80,
          url: `http://${HOST_B}/`,
          image_path: "it-software-b.png",
          page_title: "Grafana",
          technologies: ["Forgejo"],
          captured_at: new Date().toISOString(),
        },
      ])
      .execute();

    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE,
        cves: JSON.stringify([
          { id: FP_CVE, cvssScore: 9.8, cvssSeverity: "CRITICAL", description: "a false positive" },
          { id: ACCEPTED_CVE, cvssScore: 8.1, cvssSeverity: "HIGH", description: "an accepted risk" },
          { id: OPEN_CVE, cvssScore: 5.0, cvssSeverity: "MEDIUM", description: "untriaged" },
        ]),
      })
      .onConflict((oc) => oc.column("cpe").doUpdateSet({ cves: (eb) => eb.ref("excluded.cves") }))
      .execute();
  });

  afterAll(async () => {
    await db.deleteFrom("finding_triage").where("cve_id", "in", [FP_CVE, ACCEPTED_CVE, OPEN_CVE]).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "in", [FP_CVE, ACCEPTED_CVE, OPEN_CVE]).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  const load = async (): Promise<SoftwareRow[]> => {
    const res = await client.get("/api/software");
    expect(res.status).toBe(200);
    return res.body.items.filter((r: SoftwareRow) => r.scanners.includes(agent.name));
  };

  const find = (rows: SoftwareRow[], version: string | null) =>
    rows.find((r) => r.product === "TestServer" && r.version === version);

  it("groups by product and version, counting hosts and ports separately", async () => {
    const rows = await load();
    const v123 = find(rows, "1.2.3");
    expect(v123).toBeDefined();
    // HOST_A on two ports plus HOST_B on one: two hosts, three ports.
    // Counting ports as hosts is the mistake this pins down.
    expect(v123!.hosts).toBe(2);
    expect(v123!.ports).toBe(3);

    const v200 = find(rows, "2.0.0");
    expect(v200!.hosts).toBe(1);
    expect(v200!.ports).toBe(1);
  });

  it("treats a missing and an empty version as one undetermined row", async () => {
    const rows = await load();
    const unknownRows = rows.filter((r) => r.product === "TestServer" && r.version === null);
    // One row, not two - '' and NULL are the same statement about the
    // same software and must not split it.
    expect(unknownRows).toHaveLength(1);
    expect(unknownRows[0].hosts).toBe(1);
    expect(unknownRows[0].ports).toBe(2);
  });

  it("ignores products only ever seen on a closed port", async () => {
    const rows = await load();
    expect(rows.find((r) => r.product === "ClosedOnlyProduct")).toBeUndefined();
  });

  it("counts only versions whose ports actually carry the CPE", async () => {
    const rows = await load();
    // 1.2.3's ports carry the CPE; 2.0.0's port does not, so it has no
    // CVEs even though it is the same product.
    expect(find(rows, "1.2.3")!.cveCount).toBe(3);
    expect(find(rows, "2.0.0")!.cveCount).toBe(0);
    expect(find(rows, "2.0.0")!.maxCvssScore).toBeNull();
  });

  it("honours triage the way the host list's risk indicator does", async () => {
    const hosts = await db
      .selectFrom("hosts")
      .select(["id"])
      .where("scanner_agent_id", "=", agent.id)
      .execute();
    // A false positive is not current exposure and drops out; an accepted
    // risk still is, and stays. Applied per host, so triaging on every
    // host is what removes it from a fleet-wide count.
    for (const host of hosts) {
      for (const [cveId, state] of [
        [FP_CVE, "false_positive"],
        [ACCEPTED_CVE, "accepted_risk"],
      ] as const) {
        await db
          .insertInto("finding_triage")
          .values({ kind: "cve", host_id: host.id, cve_id: cveId, state, created_by: admin.username })
          .onConflict((oc) => oc.doNothing())
          .execute();
      }
    }

    const rows = await load();
    const v123 = find(rows, "1.2.3")!;
    // The 9.8 false positive is gone; the 8.1 accepted risk is not, so it
    // becomes the highest score.
    expect(v123.cveCount).toBe(2);
    expect(v123.maxCvssScore).toBeCloseTo(8.1, 5);
  });

  it("flags a KEV-listed CVE on the version that carries it", async () => {
    await db
      .insertInto("kev_cache")
      .values({
        cve_id: OPEN_CVE,
        vendor_project: "Example",
        product: "TestServer",
        vulnerability_name: "Test KEV entry",
        date_added: "2026-01-01",
        known_ransomware_campaign_use: "Unknown",
      })
      .onConflict((oc) => oc.doNothing())
      .execute();

    const rows = await load();
    expect(find(rows, "1.2.3")!.hasKev).toBe(true);
    expect(find(rows, "2.0.0")!.hasKev).toBe(false);
  });


  it("lists a web application that only a page title reveals", async () => {
    // Grafana appears in no service banner and no technology list - the
    // page title is the only evidence it is running at all, which is the
    // whole reason that source exists.
    const rows = await load();
    const grafana = rows.find((r) => r.product === "Grafana");
    expect(grafana).toBeDefined();
    expect(grafana!.sources).toEqual(["title"]);
    expect(grafana!.version).toBeNull();
    // Two hosts, two ports - counted from the newest capture of each.
    expect(grafana!.hosts).toBe(2);
  });

  it("lists a technology fingerprint as its own row, with a version", async () => {
    const rows = await load();
    const forgejo = rows.find((r) => r.product === "Forgejo");
    expect(forgejo).toBeDefined();
    expect(forgejo!.sources).toEqual(["web"]);

    const jquery = rows.find((r) => r.product === "jQuery");
    expect(jquery!.version).toBe("3.7.1");
  });

  it("merges a product both nmap and the web fingerprint saw, rather than listing it twice", async () => {
    const rows = await load();
    const matches = rows.filter((r) => r.product.toLowerCase() === "testserver" && r.version === "1.2.3");
    // One row, not two - and it records both sources.
    expect(matches).toHaveLength(1);
    expect(matches[0].sources.sort()).toEqual(["service", "web"]);
    // The service capitalisation wins, being the stronger identification.
    expect(matches[0].product).toBe("TestServer");
    // Merged counts are the maximum of the two observations, never their
    // sum: they are two views of the same thing.
    expect(matches[0].hosts).toBe(2);
  });

  it("ignores all but the newest capture of a (host, port)", async () => {
    const rows = await load();
    expect(rows.find((r) => r.product === "AncientTech")).toBeUndefined();
    expect(rows.find((r) => r.product === "Something Ancient")).toBeUndefined();
  });

  it("hides software from a scanner the user is not assigned to", async () => {
    const other = await createTestUser("user");
    try {
      // An assignment to a different agent means this fleet-wide page
      // must not leak the software behind it - the same restriction
      // every other fleet-wide read applies.
      const otherAgent = await createTestAgent("it-software-other");
      try {
        await db
          .insertInto("user_scanner_agents")
          .values({ user_id: other.id, scanner_agent_id: otherAgent.id })
          .execute();
        const restricted = await loginAs(other.username, other.password);
        const res = await restricted.get("/api/software");
        expect(res.status).toBe(200);
        expect(res.body.items.some((r: SoftwareRow) => r.product === "TestServer")).toBe(false);
      } finally {
        await deleteTestAgent(otherAgent.id);
      }
    } finally {
      await deleteTestUser(other.id);
    }
  });
});
