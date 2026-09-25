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

const IP_NO_DNS = "240.80.0.10";
const IP_WITH_DNS = "240.80.0.11";

describe("derived host identity", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;

  const ingest = async (hosts: unknown[]) => {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.80.0.0/24", portSpec: "445" });
    const res = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: job.body.id, hosts });
    expect(res.status).toBe(204);
  };

  const load = async (ip: string) =>
    db
      .selectFrom("hosts")
      .select([
        "hostname",
        "mac_address",
        "mac_vendor",
        "derived_hostname",
        "derived_hostname_source",
        "derived_mac_address",
        "derived_mac_vendor",
        "derived_mac_source",
      ])
      .where("ip", "=", ip)
      .where("scanner_agent_id", "=", agent.id)
      .executeTakeFirstOrThrow();

  beforeAll(async () => {
    agent = await createTestAgent("it-derived-agent");
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

  it("stores what the scanner derived, with its source", async () => {
    await ingest([
      {
        ip: IP_NO_DNS,
        derivedHostname: "ws-app-01.corp.example.internal",
        derivedHostnameSource: "rdp-certificate",
        derivedMacAddress: "00:15:5D:01:2A:0B",
        derivedMacVendor: "Microsoft",
        derivedMacSource: "nbstat",
        ports: [{ port: 445, protocol: "tcp", state: "open", serviceName: "microsoft-ds" }],
      },
    ]);

    const host = await load(IP_NO_DNS);
    expect(host.hostname).toBeNull();
    expect(host.mac_address).toBeNull();
    expect(host.derived_hostname).toBe("ws-app-01.corp.example.internal");
    expect(host.derived_hostname_source).toBe("rdp-certificate");
    expect(host.derived_mac_address).toBe("00:15:5D:01:2A:0B");
    expect(host.derived_mac_vendor).toBe("Microsoft");
    expect(host.derived_mac_source).toBe("nbstat");
  });

  // The point of separate columns: a real PTR record and a machine's own
  // claim coexist rather than one replacing the other.
  it("keeps a real hostname and a derived one side by side when they disagree", async () => {
    await ingest([
      {
        ip: IP_WITH_DNS,
        hostname: "filer01.corp.example.internal",
        derivedHostname: "FILER02",
        derivedHostnameSource: "nbstat",
        ports: [{ port: 445, protocol: "tcp", state: "open", serviceName: "microsoft-ds" }],
      },
    ]);

    const host = await load(IP_WITH_DNS);
    expect(host.hostname).toBe("filer01.corp.example.internal");
    expect(host.derived_hostname).toBe("FILER02");
  });

  // A scan that finds no SMB or RDP evidence this time must not erase
  // what an earlier one worked out - the same coalescing os_family and
  // mac_address already get for their own reasons.
  it("does not erase a derived value on a later scan that finds nothing", async () => {
    await ingest([
      { ip: IP_NO_DNS, ports: [{ port: 445, protocol: "tcp", state: "open", serviceName: "microsoft-ds" }] },
    ]);

    const host = await load(IP_NO_DNS);
    expect(host.derived_hostname).toBe("ws-app-01.corp.example.internal");
    expect(host.derived_hostname_source).toBe("rdp-certificate");
    expect(host.derived_mac_address).toBe("00:15:5D:01:2A:0B");
  });

  // ...and the source always describes the value beside it, never a
  // leftover from different evidence.
  it("replaces the source together with the value it describes", async () => {
    await ingest([
      {
        ip: IP_NO_DNS,
        derivedHostname: "ws-app-01",
        derivedHostnameSource: "smb-os-discovery",
        ports: [{ port: 445, protocol: "tcp", state: "open", serviceName: "microsoft-ds" }],
      },
    ]);

    const host = await load(IP_NO_DNS);
    expect(host.derived_hostname).toBe("ws-app-01");
    expect(host.derived_hostname_source).toBe("smb-os-discovery");
  });

  it("returns both through the host list and the detail endpoint", async () => {
    const list = await client.get("/api/hosts?q=240.80.0.10");
    expect(list.status).toBe(200);
    const listed = list.body.items.find((h: { ip: string }) => h.ip === IP_NO_DNS);
    expect(listed.derived_hostname).toBe("ws-app-01");
    expect(listed.derived_hostname_source).toBe("smb-os-discovery");

    const detail = await client.get(`/api/hosts/${listed.id}`);
    expect(detail.status).toBe(200);
    expect(detail.body.host.derived_hostname).toBe("ws-app-01");
    expect(detail.body.host.derived_mac_address).toBe("00:15:5D:01:2A:0B");
  });

  // A scanner too old to send these fields must behave exactly as before.
  it("accepts a submission with none of the fields at all", async () => {
    await ingest([
      { ip: "240.80.0.12", ports: [{ port: 445, protocol: "tcp", state: "open", serviceName: "microsoft-ds" }] },
    ]);
    const host = await load("240.80.0.12");
    expect(host.derived_hostname).toBeNull();
    expect(host.derived_mac_address).toBeNull();
  });
});
