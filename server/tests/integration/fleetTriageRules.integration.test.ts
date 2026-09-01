import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, loginAs, type TestUser } from "./helpers";

// A CVE that a CPE mismatch attaches to every host had to be dismissed
// once per host - endless, and re-opened by the next host discovered.
describe("fleet-wide triage rules", () => {
  let admin: TestUser;
  let operator: TestUser;
  const ruleIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
  });

  afterAll(async () => {
    await db.deleteFrom("finding_triage_rules").where("id", "in", ruleIds.length ? ruleIds : ["00000000-0000-0000-0000-000000000000"]).execute();
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("is admin-only", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.put("/api/finding-triage/rules").send({
      kind: "cve",
      cveId: "CVE-2099-0001",
      state: "false_positive",
    });
    expect(res.status).toBe(403);
  });

  it("creates a rule and revises it in place rather than duplicating", async () => {
    const client = await loginAs(admin.username, admin.password);
    const created = await client.put("/api/finding-triage/rules").send({
      kind: "cve",
      cveId: "CVE-2099-0002",
      state: "false_positive",
      note: "CPE matches a product we do not run",
    });
    expect(created.status).toBe(200);
    ruleIds.push(created.body.id);

    const revised = await client.put("/api/finding-triage/rules").send({
      kind: "cve",
      cveId: "CVE-2099-0002",
      state: "accepted_risk",
    });
    expect(revised.status).toBe(200);
    expect(revised.body.id).toBe(created.body.id);
    expect(revised.body.state).toBe("accepted_risk");

    const list = await client.get("/api/finding-triage/rules");
    expect(list.body.filter((r: { cve_id: string }) => r.cve_id === "CVE-2099-0002")).toHaveLength(1);
  });

  it("rejects a rule that names the wrong identifier for its kind", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.put("/api/finding-triage/rules").send({
      kind: "cve",
      templateId: "some-template",
      state: "fixed",
    });
    expect(res.status).toBe(400);
  });

  it("deletes a rule", async () => {
    const client = await loginAs(admin.username, admin.password);
    const created = await client.put("/api/finding-triage/rules").send({
      kind: "nuclei",
      templateId: "it-template-x",
      state: "false_positive",
    });
    expect(created.status).toBe(200);

    expect((await client.delete(`/api/finding-triage/rules/${created.body.id}`)).status).toBe(204);
    expect((await client.delete(`/api/finding-triage/rules/${created.body.id}`)).status).toBe(404);
  });
});
