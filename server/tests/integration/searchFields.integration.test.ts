import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// The dashboard's free-text search used to miss words the screenshot
// gallery found for the same host: page titles, URLs, web technologies,
// response headers, OS and device type, the name a host reports itself,
// service versions and tags. One host per field, each with a word that
// appears nowhere else, so every assertion proves exactly one field.
describe("dashboard free-text search covers what the gallery searches", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let jobId: string;
  const ips: Record<string, string> = {};
  const word = (field: string) => `zq${field}${Date.now() % 100000}`;
  const words: Record<string, string> = {};

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-search-fields");
    jobId = (
      await db
        .insertInto("scan_jobs")
        .values({ scanner_agent_id: agent.id, target_spec: "192.0.2.0/24", port_spec: "80", status: "completed" })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;

    const fields = ["title", "url", "tech", "header", "osname", "device", "derived", "version", "extra", "tag"];
    let n = 10;
    for (const f of fields) {
      words[f] = word(f);
      ips[f] = `192.0.2.${n++}`;
      const host = await db
        .insertInto("hosts")
        .values({
          ip: ips[f],
          scanner_agent_id: agent.id,
          os_name: f === "osname" ? `Linux ${words[f]}` : null,
          device_type: f === "device" ? words[f] : null,
          derived_hostname: f === "derived" ? `${words[f]}.corp.example` : null,
        } as never)
        .returning("id")
        .executeTakeFirstOrThrow();
      await db
        .insertInto("host_port_observations")
        .values({
          host_id: host.id,
          scan_job_id: jobId,
          port: 80,
          protocol: "tcp",
          state: "open",
          service_name: "http",
          service_version: f === "version" ? `2.4-${words[f]}` : null,
          extra_info: f === "extra" ? `(${words[f]})` : null,
        } as never)
        .execute();
      await db
        .insertInto("screenshots")
        .values({
          host_id: host.id,
          scan_job_id: jobId,
          port: 80,
          url: f === "url" ? `http://${ips[f]}/${words[f]}/login` : `http://${ips[f]}/`,
          image_path: "none.png",
          page_title: f === "title" ? `Welcome to ${words[f]}` : null,
          technologies: f === "tech" ? [`${words[f]}:1.2`] : null,
          headers: f === "header" ? JSON.stringify({ Server: words[f] }) : null,
        } as never)
        .execute();
      if (f === "tag") await db.insertInto("host_tags").values({ host_id: host.id, tag: words[f] }).execute();
    }
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_jobs").where("id", "=", jobId).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  // A header typed the way it is written, "Name: value", matches that
  // header only - not another host with the same name and another value.
  it("finds a header as Name: value", async () => {
    const extra = async (ip: string, headers: Record<string, string>) => {
      const host = await db.insertInto("hosts").values({ ip, scanner_agent_id: agent.id } as never).returning("id").executeTakeFirstOrThrow();
      await db.insertInto("host_port_observations").values({ host_id: host.id, scan_job_id: jobId, port: 80, protocol: "tcp", state: "open", service_name: "http" } as never).execute();
      await db.insertInto("screenshots").values({ host_id: host.id, scan_job_id: jobId, port: 80, url: `http://${ip}/`, image_path: "none.png", headers: JSON.stringify(headers) } as never).execute();
    };
    await extra("192.0.2.40", { "X-Powered-By": "PHP/8.3.33", Server: "Apache" });
    await extra("192.0.2.41", { "X-Powered-By": "Express" });
    const ips = async (q: string) =>
      (await client.get(`/api/hosts?q=${encodeURIComponent(q)}&scannerAgentId=${agent.id}`)).body.items.map((h: { ip: string }) => h.ip).sort();
    expect(await ips("X-Powered-By: PHP")).toEqual(["192.0.2.40"]);
    expect(await ips("x-powered-by: express")).toEqual(["192.0.2.41"]);
    expect(await ips("Server: Apache")).toEqual(["192.0.2.40"]);
    expect(await ips("X-Powered-By")).toEqual(["192.0.2.40", "192.0.2.41"]);
  });

  it.each(["title", "url", "tech", "header", "osname", "device", "derived", "version", "extra", "tag"])(
    "finds a host by its %s",
    async (field) => {
      // Upper-cased to hold down the case-insensitivity too.
      const res = await client.get(`/api/hosts?q=${encodeURIComponent(words[field].toUpperCase())}`);
      expect(res.status).toBe(200);
      expect(res.body.items.map((h: { ip: string }) => h.ip)).toEqual([ips[field]]);
    }
  );
});
