import { readFileSync } from "node:fs";
import path from "node:path";
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
  type TestAgent,
  type TestUser,
} from "./helpers";

const REAL_SAMPLE = readFileSync(path.join(__dirname, "../fixtures/nmap-real-sample.xml"), "utf8");
// Class E (240.0.0.0/4) - reserved, so this can't collide with real data.
const IMPORT_IP = "240.50.0.7";
const rewritten = REAL_SAMPLE.replace(/127\.0\.0\.1/g, IMPORT_IP);

// Everything in this database existed because a PortTorch scanner found
// it. These cover the way in for an nmap run from a network with no
// agent - and, more importantly, that it lands through the same path a
// scanner submission does rather than a parallel insert.
describe("importing an nmap XML report", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let viewer: TestUser;
  let scanJobId: string;
  let operatorClient: Awaited<ReturnType<typeof loginAs>>;
  let viewerClient: Awaited<ReturnType<typeof loginAs>>;

  beforeAll(async () => {
    agent = await createTestAgent("it-import-agent");
    operator = await createTestUser("operator");
    viewer = await createTestUser("user");
    // Built once here rather than per test: a supertest request object is
    // itself thenable, so `await someAsyncFn()` returning one would fire
    // the request before .field()/.attach() were ever called.
    operatorClient = await loginAs(operator.username, operator.password);
    viewerClient = await loginAs(viewer.username, viewer.password);
  });

  afterAll(async () => {
    await sql`DELETE FROM hosts WHERE ip = ${IMPORT_IP}::inet`.execute(db);
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(operator.id);
    await deleteTestUser(viewer.id);
    await closeDb();
  });


  it("refuses a read-only user", async () => {
    const res = await viewerClient.post("/api/imports/nmap")
      .field("scannerAgentId", agent.id)
      .attach("file", Buffer.from(rewritten), "scan.xml");
    expect(res.status).toBe(403);
  });

  it("requires a real scanner agent to attribute the results to", async () => {
    // Host identity is (ip, scanner_agent_id), so unattributed results
    // could not be told apart from the same private address on another
    // scanner's network.
    const res = await operatorClient.post("/api/imports/nmap")
      .field("scannerAgentId", "00000000-0000-0000-0000-000000000000")
      .attach("file", Buffer.from(rewritten), "scan.xml");
    expect(res.status).toBe(400);
  });

  it("rejects a file that is not an nmap report", async () => {
    const res = await operatorClient.post("/api/imports/nmap")
      .field("scannerAgentId", agent.id)
      .attach("file", Buffer.from("<other><thing/></other>"), "scan.xml");
    expect(res.status).toBe(400);
    expect(String(res.body.error)).toContain("nmap");
  });

  it("imports hosts, ports and service detection", async () => {
    const res = await operatorClient.post("/api/imports/nmap")
      .field("scannerAgentId", agent.id)
      .field("targetSpec", "240.50.0.0/24")
      .attach("file", Buffer.from(rewritten), "scan.xml");
    expect(res.status).toBe(201);
    expect(res.body.hostsImported).toBe(1);
    expect(res.body.openPortsFound).toBe(2);
    // Taken from <scaninfo>, which is what lets the ingest path close
    // ports for an import exactly as it does for a scan.
    expect(res.body.portSpec).toBe("2222,8080,9999");
    scanJobId = res.body.scanJobId;

    const list = await operatorClient.get(`/api/hosts?q=${IMPORT_IP}`);
    expect(list.status).toBe(200);
    expect(list.body.items).toHaveLength(1);

    const detail = await operatorClient.get(`/api/hosts/${list.body.items[0].id}`);
    const ssh = detail.body.ports.find((p: { port: number }) => p.port === 2222);
    expect(ssh.service_name).toBe("ssh");
    expect(ssh.service_product).toBe("OpenSSH");
    expect(ssh.service_version).toBe("9.2p1 Debian 2");
    expect(ssh.cpes).toContain("cpe:/a:openbsd:openssh:9.2p1");
    // 9999 was scanned and closed - it must not appear as an open port.
    expect(detail.body.ports.map((p: { port: number }) => p.port).sort()).toEqual([2222, 8080]);
  });

  it("records a real scan job, so the import shows up in scan history and coverage", async () => {
    const job = await db
      .selectFrom("scan_jobs")
      .select(["target_spec", "port_spec", "status", "scanner_agent_id"])
      .where("id", "=", scanJobId)
      .executeTakeFirstOrThrow();
    // The supplied target spec wins over the discovered addresses: a /24
    // sweep that found one host covered 256 addresses, not one, and only
    // Network Coverage can use that distinction.
    expect(job.target_spec).toBe("240.50.0.0/24");
    expect(job.port_spec).toBe("2222,8080,9999");
    expect(job.status).toBe("completed");
    expect(job.scanner_agent_id).toBe(agent.id);
  });

  it("goes through the same ingest path, so auto-tags are applied", async () => {
    // serviceAutoTags is part of ingestHostPayload, not of the scanner
    // route - this is what proves the import didn't take a parallel path.
    const list = await operatorClient.get(`/api/hosts?q=${IMPORT_IP}`);
    const detail = await operatorClient.get(`/api/hosts/${list.body.items[0].id}`);
    // serviceTags.ts's own names, not the raw nmap service name - which
    // is the point: these came from the shared ingest path, not from
    // anything the import itself does.
    expect(detail.body.tags).toContain("SSH-Server");
    expect(detail.body.tags).toContain("WebServer");
  });
});
