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

// Class E (240.0.0.0/4) - reserved, never a real target.
const IP = "240.10.1.1";

describe("finding triage", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let user: TestUser;
  let client: SessionClient;
  let readOnlyClient: SessionClient;
  let hostId: string;
  let scanJobId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-triage-agent");
    operator = await createTestUser("operator");
    user = await createTestUser("user");
    client = await loginAs(operator.username, operator.password);
    readOnlyClient = await loginAs(user.username, user.password);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "443" });
    scanJobId = jobRes.body.id;

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId,
        hosts: [
          {
            ip: IP,
            ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https" }],
            nucleiFindings: [
              {
                port: 443,
                templateId: "it-triage-template",
                name: "IT triage finding",
                severity: "high",
                matchedAt: "https://240.10.1.1/admin",
              },
            ],
          },
        ],
      });

    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP).executeTakeFirstOrThrow();
    hostId = host.id;
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await deleteTestUser(operator.id);
    await deleteTestUser(user.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  const nucleiIdentity = () => ({
    kind: "nuclei" as const,
    hostId,
    templateId: "it-triage-template",
    matchedAt: "https://240.10.1.1/admin",
  });

  it("reports an untriaged finding with a null state - only exceptions get a row", async () => {
    const res = await client.get("/api/nuclei-findings");
    const finding = res.body.find((f: { template_id: string }) => f.template_id === "it-triage-template");
    expect(finding).toBeDefined();
    expect(finding.triage_state).toBeNull();
  });

  it("marks a nuclei finding as a false positive and surfaces it on the fleet-wide list", async () => {
    const res = await client
      .put("/api/finding-triage")
      .send({ ...nucleiIdentity(), state: "false_positive", note: "internal test endpoint" });
    expect(res.status).toBe(200);
    expect(res.body.state).toBe("false_positive");

    const list = await client.get("/api/nuclei-findings");
    const finding = list.body.find((f: { template_id: string }) => f.template_id === "it-triage-template");
    expect(finding.triage_state).toBe("false_positive");
    expect(finding.triage_note).toBe("internal test endpoint");
  });

  it("re-triaging the same finding updates it in place instead of erroring on a conflict", async () => {
    const res = await client.put("/api/finding-triage").send({ ...nucleiIdentity(), state: "fixed" });
    expect(res.status).toBe(200);
    expect(res.body.state).toBe("fixed");

    const rows = await db
      .selectFrom("finding_triage")
      .select(["id"])
      .where("host_id", "=", hostId)
      .where("kind", "=", "nuclei")
      .execute();
    expect(rows).toHaveLength(1);
  });

  it("survives a rescan that re-inserts the same nuclei finding row", async () => {
    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "443" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [
          {
            ip: IP,
            ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https" }],
            nucleiFindings: [
              {
                port: 443,
                templateId: "it-triage-template",
                name: "IT triage finding",
                severity: "high",
                matchedAt: "https://240.10.1.1/admin",
              },
            ],
          },
        ],
      });

    // The whole reason triage lives in its own table: nuclei_findings gets
    // a brand-new row per observation, so state stored there would vanish.
    const list = await client.get("/api/nuclei-findings");
    const finding = list.body.find((f: { template_id: string }) => f.template_id === "it-triage-template");
    expect(finding.triage_state).toBe("fixed");
  });

  it("clears triage back to untriaged", async () => {
    const res = await client.delete("/api/finding-triage").send(nucleiIdentity());
    expect(res.status).toBe(204);

    const list = await client.get("/api/nuclei-findings");
    const finding = list.body.find((f: { template_id: string }) => f.template_id === "it-triage-template");
    expect(finding.triage_state).toBeNull();
  });

  it("returns 404 when clearing a finding that was never triaged", async () => {
    const res = await client.delete("/api/finding-triage").send(nucleiIdentity());
    expect(res.status).toBe(404);
  });

  it("triages a CVE, which has no persisted finding row of its own at all", async () => {
    const res = await client
      .put("/api/finding-triage")
      .send({ kind: "cve", hostId, cveId: "CVE-1999-0001", state: "accepted_risk", note: "compensating control" });
    expect(res.status).toBe(200);

    const row = await db
      .selectFrom("finding_triage")
      .selectAll()
      .where("host_id", "=", hostId)
      .where("kind", "=", "cve")
      .executeTakeFirstOrThrow();
    expect(row.cve_id).toBe("CVE-1999-0001");
    expect(row.state).toBe("accepted_risk");
    expect(row.template_id).toBeNull();
    expect(row.matched_at).toBeNull();
    expect(row.created_by).toBe(operator.username);
  });

  it("keeps the two kinds independent - a cve and a nuclei row can coexist for one host", async () => {
    await client.put("/api/finding-triage").send({ ...nucleiIdentity(), state: "false_positive" });
    const rows = await db.selectFrom("finding_triage").select(["kind"]).where("host_id", "=", hostId).execute();
    expect(rows.map((r) => r.kind).sort()).toEqual(["cve", "nuclei"]);
  });

  it("rejects a mismatched identity shape before it reaches the database CHECK", async () => {
    const res = await client
      .put("/api/finding-triage")
      .send({ kind: "cve", hostId, templateId: "wrong-shape", state: "fixed" });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown state", async () => {
    const res = await client.put("/api/finding-triage").send({ ...nucleiIdentity(), state: "wontfix" });
    expect(res.status).toBe(400);
  });

  it("returns 404 for a host that doesn't exist", async () => {
    const res = await client
      .put("/api/finding-triage")
      .send({ kind: "cve", hostId: "00000000-0000-0000-0000-000000000000", cveId: "CVE-1999-0001", state: "fixed" });
    expect(res.status).toBe(404);
  });

  it("rejects a read-only user - triage is an operator-level annotation", async () => {
    const res = await readOnlyClient.put("/api/finding-triage").send({ ...nucleiIdentity(), state: "fixed" });
    expect(res.status).toBe(403);
  });
});
