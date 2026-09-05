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
  type TestAgent,
  type TestUser,
} from "./helpers";

// Class E (240.0.0.0/4) - reserved, so these can't collide with real data
// when the suite runs against a copy of a production database.
const CLONE_A = "240.9.1.1";
const CLONE_B = "240.9.1.2";
const UNIQUE_HOST = "240.9.1.3";
const WEAK_HOST = "240.9.1.4";

// A single key blob shared by CLONE_A and CLONE_B - the golden-image case
// this page exists to surface.
const SHARED_FP = "SHA256:sshkeystest0000000000000000000000000000000A";
const UNIQUE_FP = "SHA256:sshkeystest0000000000000000000000000000000B";
const WEAK_FP = "SHA256:sshkeystest0000000000000000000000000000000C";

interface FleetKey {
  host_ip: string;
  port: number;
  key_type: string;
  bits: number | null;
  fingerprint_sha256: string;
  shared_ip_count: number;
}

async function submit(
  agent: TestAgent,
  ip: string,
  key: { keyType: string; bits: number; fingerprintSha256: string }
): Promise<void> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: ip, portSpec: "22" });
  expect(jobRes.status).toBe(201);

  const res = await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({
      scanJobId: jobRes.body.id,
      hosts: [
        {
          ip,
          ports: [
            {
              port: 22,
              protocol: "tcp",
              state: "open",
              serviceName: "ssh",
              sshHostKeys: [key],
            },
          ],
        },
      ],
    });
  expect(res.status).toBe(204);
}

describe("fleet-wide SSH host keys", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  let admin: TestUser;

  beforeAll(async () => {
    agentA = await createTestAgent("it-sshkeys-a");
    agentB = await createTestAgent("it-sshkeys-b");
    admin = await createTestUser("admin");

    await submit(agentA, CLONE_A, { keyType: "ssh-rsa", bits: 3072, fingerprintSha256: SHARED_FP });
    await submit(agentA, CLONE_B, { keyType: "ssh-rsa", bits: 3072, fingerprintSha256: SHARED_FP });
    await submit(agentA, UNIQUE_HOST, { keyType: "ssh-ed25519", bits: 256, fingerprintSha256: UNIQUE_FP });
    await submit(agentA, WEAK_HOST, { keyType: "ssh-dss", bits: 1024, fingerprintSha256: WEAK_FP });
  });

  afterAll(async () => {
    for (const ip of [CLONE_A, CLONE_B, UNIQUE_HOST, WEAK_HOST]) {
      await db.deleteFrom("scan_jobs").where("target_spec", "=", ip).execute();
      await db.deleteFrom("hosts").where("ip", "=", ip).execute();
    }
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  async function fetchKeys(client: Awaited<ReturnType<typeof loginAs>>): Promise<Map<string, FleetKey>> {
    const res = await client.get("/api/ssh-keys");
    expect(res.status).toBe(200);
    const ours: FleetKey[] = res.body.items.filter((k: FleetKey) =>
      [CLONE_A, CLONE_B, UNIQUE_HOST, WEAK_HOST].includes(k.host_ip)
    );
    return new Map(ours.map((k) => [k.host_ip, k]));
  }

  it("counts how many addresses share the same fingerprint", async () => {
    const client = await loginAs(admin.username, admin.password);
    const byIp = await fetchKeys(client);

    expect(byIp.get(CLONE_A)!.shared_ip_count).toBe(2);
    expect(byIp.get(CLONE_B)!.shared_ip_count).toBe(2);
    expect(byIp.get(UNIQUE_HOST)!.shared_ip_count).toBe(1);
    expect(byIp.get(WEAK_HOST)!.shared_ip_count).toBe(1);

    // The raw fields the page's own risk classification reads.
    expect(byIp.get(WEAK_HOST)!.key_type).toBe("ssh-dss");
    expect(byIp.get(WEAK_HOST)!.bits).toBe(1024);
  });

  it("does not count the same machine seen by two scanners as a shared key", async () => {
    // Host identity is (ip, scanner_agent_id), so one physical box that
    // two scanners can both reach is two hosts rows legitimately serving
    // the same key. Counting rows instead of addresses would report that
    // as a cloned image on every multi-scanner deployment.
    await submit(agentB, UNIQUE_HOST, { keyType: "ssh-ed25519", bits: 256, fingerprintSha256: UNIQUE_FP });

    const client = await loginAs(admin.username, admin.password);
    const res = await client.get("/api/ssh-keys");
    expect(res.status).toBe(200);

    const forUniqueHost: FleetKey[] = res.body.items.filter((k: FleetKey) => k.host_ip === UNIQUE_HOST);
    expect(forUniqueHost).toHaveLength(2); // two hosts rows, one per scanner
    for (const k of forUniqueHost) {
      expect(k.shared_ip_count).toBe(1); // ...but only one address
    }
  });

  it("returns only the newest key per host/port/type", async () => {
    // A rescan re-reports the same key: the list must not grow a second
    // row for it, the same "most recent per identity" rule the host detail
    // page and the certificates list already use.
    const before = (await (await loginAs(admin.username, admin.password)).get("/api/ssh-keys")).body.items.filter(
      (k: FleetKey) => k.host_ip === CLONE_A
    );
    expect(before).toHaveLength(1);

    await submit(agentA, CLONE_A, { keyType: "ssh-rsa", bits: 3072, fingerprintSha256: SHARED_FP });

    const after = (await (await loginAs(admin.username, admin.password)).get("/api/ssh-keys")).body.items.filter(
      (k: FleetKey) => k.host_ip === CLONE_A
    );
    expect(after).toHaveLength(1);
  });

  it("requires authentication", async () => {
    const res = await request(getApp()).get("/api/ssh-keys");
    expect(res.status).toBe(401);
  });
});
