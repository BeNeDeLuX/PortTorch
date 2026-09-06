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

// 240.0.0.0/4 is reserved and never routable - same reasoning as
// filterNegation's own fixtures, so this can't collide with real data.
const UNBOUND_HOST = "240.12.0.1";
const SAMBA_HOST = "240.12.0.2";
// Runs Unbound, but on a port that is now closed - the case that
// separates "has this product" from "has ever had this product".
const CLOSED_UNBOUND_HOST = "240.12.0.3";
// No MAC at all, which is the overwhelming majority of any routed fleet.
const NO_MAC_HOST = "240.12.0.4";

const PROXMOX = "Proxmox Server Solutions GmbH";

// service_product ("Unbound") and mac_vendor are the two inventory
// dimensions the dashboard can filter on. Both were previously reachable
// only through free-text search or not at all.
describe("software product and manufacturer filters", () => {
  let agent: TestAgent;
  let user: TestUser;
  let client: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-inventory-agent");
    user = await createTestUser("user");
    client = await loginAs(user.username, user.password);

    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.12.0.0/24", portSpec: "53,445" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [
          {
            ip: UNBOUND_HOST,
            macAddress: "aa:bb:cc:00:00:01",
            macVendor: PROXMOX,
            ports: [
              { port: 53, protocol: "tcp", state: "open", serviceName: "domain", serviceProduct: "Unbound" },
            ],
          },
          {
            ip: SAMBA_HOST,
            macAddress: "aa:bb:cc:00:00:02",
            macVendor: "Acme Networks",
            ports: [
              {
                port: 445,
                protocol: "tcp",
                state: "open",
                serviceName: "netbios-ssn",
                serviceProduct: "Samba smbd",
                serviceVersion: "4.22.10",
              },
            ],
          },
          {
            ip: CLOSED_UNBOUND_HOST,
            macVendor: PROXMOX,
            ports: [
              { port: 53, protocol: "tcp", state: "closed", serviceName: "domain", serviceProduct: "Unbound" },
            ],
          },
          {
            ip: NO_MAC_HOST,
            ports: [{ port: 445, protocol: "tcp", state: "open", serviceName: "netbios-ssn" }],
          },
        ],
      });
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(user.id);
    await closeDb();
  });

  const ips = (body: { items: Array<{ ip: string }> }) => body.items.map((h) => h.ip).sort();

  it("filters to hosts running a product", async () => {
    const res = await client.get(`/api/hosts?product=Unbound&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(ips(res.body)).toEqual([UNBOUND_HOST]);
  });

  it("does not match a product whose only port is closed", async () => {
    // The state = 'open' condition. Without it this host would count as
    // running Unbound on the strength of a port that no longer answers.
    const res = await client.get(`/api/hosts?product=Unbound&scannerAgentId=${agent.id}`);
    expect(ips(res.body)).not.toContain(CLOSED_UNBOUND_HOST);
  });

  it("excludes a product with a leading minus, keeping the closed-port host", async () => {
    const res = await client.get(`/api/hosts?product=-Unbound&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    // CLOSED_UNBOUND_HOST is included precisely because it does not
    // currently run Unbound - the mirror image of the case above.
    expect(ips(res.body)).toEqual([CLOSED_UNBOUND_HOST, NO_MAC_HOST, SAMBA_HOST].sort());
  });

  it("filters by manufacturer", async () => {
    const res = await client.get(`/api/hosts?macVendor=${encodeURIComponent(PROXMOX)}&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(ips(res.body)).toEqual([CLOSED_UNBOUND_HOST, UNBOUND_HOST].sort());
  });

  it("excluding a manufacturer keeps hosts that have no MAC at all", async () => {
    // The trap this pins down: `NOT (mac_vendor IN (...))` is NULL, not
    // true, for a host with no MAC - so a plain NOT IN silently drops
    // every host reached across a router, which on a real fleet is
    // almost all of them.
    const res = await client.get(`/api/hosts?macVendor=-${encodeURIComponent(PROXMOX)}&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(ips(res.body)).toEqual([NO_MAC_HOST, SAMBA_HOST].sort());
  });

  it("finds a host by its manufacturer through free-text search", async () => {
    const res = await client.get(`/api/hosts?q=Proxmox&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(ips(res.body)).toEqual([CLOSED_UNBOUND_HOST, UNBOUND_HOST].sort());
  });

  it("offers both dimensions as facets, counting hosts", async () => {
    const res = await client.get(`/api/hosts/facets?scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(res.body.products).toContainEqual({ product: "Unbound", count: 1 });
    expect(res.body.products).toContainEqual({ product: "Samba smbd", count: 1 });
    expect(res.body.macVendors).toContainEqual({ macVendor: PROXMOX, count: 2 });
  });

  it("narrows a facet's counts by the other active filters", async () => {
    // The documented trap: a facet route with a "skip the join when no
    // filter is active" fast path must treat these new filters as active
    // too, or the sidebar keeps reporting fleet-wide counts.
    const res = await client.get(`/api/hosts/facets?product=Unbound&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(res.body.macVendors).toContainEqual({ macVendor: PROXMOX, count: 1 });
  });

  it("carries the manufacturer into both CSV exports", async () => {
    const summary = await client.get(`/api/hosts/export.csv?scannerAgentId=${agent.id}`);
    expect(summary.status).toBe(200);
    const [header, ...rows] = summary.text.split("\r\n");
    expect(header.split(",")).toContain("mac_vendor");
    const vendorIndex = header.split(",").indexOf("mac_vendor");
    const unboundRow = rows.find((r) => r.startsWith(`"${UNBOUND_HOST}"`) || r.startsWith(UNBOUND_HOST));
    expect(unboundRow).toBeDefined();
    // Column position, not just presence: a header added without its
    // value shifts every field after it.
    expect(unboundRow!.split(",")[vendorIndex]).toContain("Proxmox");

    const perPort = await client.get(`/api/hosts/export.csv?detail=port&scannerAgentId=${agent.id}`);
    expect(perPort.status).toBe(200);
    expect(perPort.text.split("\r\n")[0].split(",")).toContain("mac_vendor");
  });
});
