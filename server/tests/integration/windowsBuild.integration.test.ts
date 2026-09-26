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

// The exact Windows build the scanner reads out of an NTLM message (see
// scanner/internal/pipeline/windowsversion.go). Only the build is stored;
// what it is called and whether it is still supported is derived on read
// in the frontend, so nothing here asserts a release name.
const IP = "240.81.0.10";
const IP_NO_NTLM = "240.81.0.11";

describe("windows build", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;

  const ingest = async (hosts: unknown[]) => {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.81.0.0/24", portSpec: "3389" });
    const res = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: job.body.id, hosts });
    expect(res.status).toBe(204);
  };

  const load = async (ip: string) =>
    db
      .selectFrom("hosts")
      .select(["os_family", "windows_build", "windows_build_source"])
      .where("ip", "=", ip)
      .where("scanner_agent_id", "=", agent.id)
      .executeTakeFirstOrThrow();

  const port = { port: 3389, protocol: "tcp", state: "open", serviceName: "ms-wbt-server" };

  beforeAll(async () => {
    agent = await createTestAgent("it-winbuild-agent");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  it("stores the build and which script reported it", async () => {
    await ingest([
      { ip: IP, windowsBuild: "10.0.14393", windowsBuildSource: "rdp-ntlm-info", ports: [port] },
    ]);

    const host = await load(IP);
    expect(host.windows_build).toBe("10.0.14393");
    expect(host.windows_build_source).toBe("rdp-ntlm-info");
    // Deliberately independent of nmap's own -O fingerprint, which is
    // root-only and says nothing more specific than "Windows".
    expect(host.os_family).toBeNull();
  });

  // A rescan that reaches no NTLM-capable service - a firewall change, or
  // simply a scan of a narrower port spec - must not erase a build an
  // earlier scan established. Same coalescing os_family and mac_address
  // already get for their own reasons.
  it("does not erase the build on a later scan that reports none", async () => {
    await ingest([{ ip: IP, ports: [port] }]);

    const host = await load(IP);
    expect(host.windows_build).toBe("10.0.14393");
    expect(host.windows_build_source).toBe("rdp-ntlm-info");
  });

  // The source must always describe the build beside it, never survive as
  // a leftover from different evidence.
  it("replaces the source together with the build it describes", async () => {
    await ingest([
      { ip: IP, windowsBuild: "10.0.17763", windowsBuildSource: "http-ntlm-info", ports: [port] },
    ]);

    const host = await load(IP);
    expect(host.windows_build).toBe("10.0.17763");
    expect(host.windows_build_source).toBe("http-ntlm-info");
  });

  it("returns it through the host list, the detail endpoint and the JSON export", async () => {
    const list = await client.get(`/api/hosts?q=${IP}`);
    expect(list.status).toBe(200);
    const listed = list.body.items.find((h: { ip: string }) => h.ip === IP);
    expect(listed.windows_build).toBe("10.0.17763");
    expect(listed.windows_build_source).toBe("http-ntlm-info");

    const detail = await client.get(`/api/hosts/${listed.id}`);
    expect(detail.status).toBe(200);
    expect(detail.body.host.windows_build).toBe("10.0.17763");
    expect(detail.body.host.windows_build_source).toBe("http-ntlm-info");

    const json = await client.get(`/api/hosts/export.json?q=${IP}`);
    expect(json.status).toBe(200);
    const exported = (json.body as Array<{ ip: string; windowsBuild: string | null }>).find((h) => h.ip === IP);
    expect(exported?.windowsBuild).toBe("10.0.17763");
  });

  // A scanner too old to send the fields at all, and a host that is not
  // Windows: both look the same here, and both must be fine.
  it("accepts a submission without the fields", async () => {
    await ingest([{ ip: IP_NO_NTLM, ports: [port] }]);

    const host = await load(IP_NO_NTLM);
    expect(host.windows_build).toBeNull();
    expect(host.windows_build_source).toBeNull();
  });
});
