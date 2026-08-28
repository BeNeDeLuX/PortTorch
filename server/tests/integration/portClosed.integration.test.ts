import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, deleteTestAgent, getApp, type TestAgent } from "./helpers";

// 240.0.0.0/4 is reserved and never routable, so this can't collide with
// real data if the suite is ever run against a copy of a live database -
// same convention as hostIdentity.integration.test.ts.
const IP = "240.9.9.9";

// Neither masscan nor nmap ever reports a closed port, so "this port
// closed" has to be inferred: previously open, absent from this scan's
// results, and inside the port spec that scan actually asked for. That
// last condition is the whole point - without it a targeted rescan of one
// port would claim every other known port on the host had just closed.
describe("port.closed detection", () => {
  let agent: TestAgent;

  beforeAll(async () => {
    agent = await createTestAgent("it-portclosed-agent");
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function scan(portSpec: string, openPorts: Array<number | [number, string]>): Promise<void> {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec });
    expect(job.status).toBe(201);

    const res = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [
          {
            ip: IP,
            hostname: "portclosed.internal",
            ports: openPorts.map((p) => {
              const [port, protocol] = Array.isArray(p) ? p : [p, "tcp"];
              return { port, protocol, state: "open", serviceName: "http" };
            }),
          },
        ],
      });
    expect(res.status).toBe(204);
  }

  async function currentState(port: number, protocol = "tcp"): Promise<string | undefined> {
    const row = await db
      .selectFrom("current_host_ports")
      .innerJoin("hosts", "hosts.id", "current_host_ports.host_id")
      .select(["current_host_ports.state as state"])
      .where("hosts.ip", "=", IP)
      .where("hosts.scanner_agent_id", "=", agent.id)
      .where("current_host_ports.port", "=", port)
      .where("current_host_ports.protocol", "=", protocol)
      .executeTakeFirst();
    return row?.state;
  }

  it("records a closed observation when a covered port stops answering", async () => {
    await scan("22,80,443", [22, 80, 443]);
    expect(await currentState(22)).toBe("open");

    // Same port spec, 22 no longer reported: the scan looked and didn't
    // find it.
    await scan("22,80,443", [80, 443]);
    expect(await currentState(22)).toBe("closed");
    expect(await currentState(80)).toBe("open");
  });

  it("leaves ports the scan never asked about untouched", async () => {
    await scan("22,80,443", [22, 80, 443]);
    expect(await currentState(22)).toBe("open");

    // The bug this exists to prevent: a targeted rescan of 443 alone must
    // say nothing whatsoever about 22 or 80.
    await scan("443", [443]);
    expect(await currentState(22)).toBe("open");
    expect(await currentState(80)).toBe("open");
    expect(await currentState(443)).toBe("open");
  });

  it("treats a range spec as covering the ports inside it", async () => {
    await scan("22,80,443", [22, 80, 443]);
    await scan("1-1000", [80, 443]);
    expect(await currentState(22)).toBe("closed");
  });

  it("does not carry a closed port's stale service details forward", async () => {
    await scan("8080", [8080]);
    await scan("8080", []);
    const row = await db
      .selectFrom("current_host_ports")
      .innerJoin("hosts", "hosts.id", "current_host_ports.host_id")
      .select(["current_host_ports.state as state", "current_host_ports.service_name as service_name"])
      .where("hosts.ip", "=", IP)
      .where("hosts.scanner_agent_id", "=", agent.id)
      .where("current_host_ports.port", "=", 8080)
      .executeTakeFirstOrThrow();
    expect(row.state).toBe("closed");
    // Would otherwise keep matching a service:http filter it no longer
    // belongs in.
    expect(row.service_name).toBeNull();
  });

  it("never concludes a TCP port closed from a UDP scan, or the reverse", async () => {
    // The failure this guards against: host_port_observations keys on
    // (port, protocol), so port 53 exists twice - a UDP sweep that finds
    // nothing must not close TCP/53 alongside it.
    await scan("53,U:53", [53, [53, "udp"]]);
    expect(await currentState(53, "tcp")).toBe("open");
    expect(await currentState(53, "udp")).toBe("open");

    // UDP-only rescan, UDP/53 gone: only the UDP row may change.
    await scan("U:53", []);
    expect(await currentState(53, "udp")).toBe("closed");
    expect(await currentState(53, "tcp")).toBe("open");
  });

  it("does not fire on a host's very first scan", async () => {
    // A brand new host has no prior open ports to lose - and the check is
    // skipped entirely for an inserted host, so an empty first scan can't
    // manufacture closed rows out of nothing.
    const freshIp = "240.9.9.10";
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: freshIp, portSpec: "1-1000" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: job.body.id, hosts: [{ ip: freshIp, ports: [{ port: 80, protocol: "tcp", state: "open" }] }] });

    const rows = await db
      .selectFrom("current_host_ports")
      .innerJoin("hosts", "hosts.id", "current_host_ports.host_id")
      .select(["current_host_ports.port as port", "current_host_ports.state as state"])
      .where("hosts.ip", "=", freshIp)
      .where("hosts.scanner_agent_id", "=", agent.id)
      .execute();
    expect(rows).toEqual([{ port: 80, state: "open" }]);

    await db.deleteFrom("hosts").where("ip", "=", freshIp).where("scanner_agent_id", "=", agent.id).execute();
  });
});
