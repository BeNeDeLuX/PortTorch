import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target.
const IP = "240.6.4.1";
const FTP_LISTING = "Anonymous FTP login allowed (FTP code 230)\n-rw-r--r-- 1 0 0 123 Jan 01 2020 readme-secret.txt";
const SMB_SHARES = "account_used: guest\nprint$:\n  Anonymous access: READ\nbackup-vault:\n  Anonymous access: READ/WRITE";

describe("FTP anonymous listing / SMB share enumeration (ftp-anon, smb-enum-shares)", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let hostId: string;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-ftpsmb-agent");

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "21,445" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [
          {
            ip: IP,
            hostname: "it-ftpsmb-host",
            ports: [
              { port: 21, protocol: "tcp", state: "open", serviceName: "ftp", ftpAnonListing: FTP_LISTING },
              { port: 445, protocol: "tcp", state: "open", serviceName: "microsoft-ds", smbShares: SMB_SHARES },
            ],
          },
        ],
      });

    const hostRow = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP).executeTakeFirstOrThrow();
    hostId = hostRow.id;
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("id", "=", hostId).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("GET /api/hosts/:id returns ftp_anon_listing on the FTP port and smb_shares on the SMB port, not swapped", async () => {
    const res = await client.get(`/api/hosts/${hostId}`);
    expect(res.status).toBe(200);

    const ports = res.body.ports as Array<{ port: number; ftp_anon_listing: string | null; smb_shares: string | null }>;
    const ftpPort = ports.find((p) => p.port === 21);
    const smbPort = ports.find((p) => p.port === 445);

    expect(ftpPort?.ftp_anon_listing).toBe(FTP_LISTING);
    expect(ftpPort?.smb_shares).toBeNull();
    expect(smbPort?.smb_shares).toBe(SMB_SHARES);
    expect(smbPort?.ftp_anon_listing).toBeNull();
  });

  it("free-text search matches a filename inside the FTP listing", async () => {
    const res = await client.get("/api/hosts").query({ q: "readme-secret" });
    expect(res.status).toBe(200);
    expect((res.body.items as Array<{ id: string }>).some((h) => h.id === hostId)).toBe(true);
  });

  it("free-text search matches a share name inside the SMB enumeration", async () => {
    const res = await client.get("/api/hosts").query({ q: "backup-vault" });
    expect(res.status).toBe(200);
    expect((res.body.items as Array<{ id: string }>).some((h) => h.id === hostId)).toBe(true);
  });

  it("free-text search for an unrelated term does not match", async () => {
    const res = await client.get("/api/hosts").query({ q: "no-such-term-anywhere-xyz" });
    expect(res.status).toBe(200);
    expect((res.body.items as Array<{ id: string }>).some((h) => h.id === hostId)).toBe(false);
  });
});
