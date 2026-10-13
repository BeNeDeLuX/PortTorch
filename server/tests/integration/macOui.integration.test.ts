import http from "http";
import type { AddressInfo } from "net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { fillMacVendors, syncMacOui } from "../../src/macOui/sync";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, loginAs, type TestAgent } from "./helpers";

// nmap's list has the short names and an MA-S block; the IEEE file adds
// a prefix nmap lacks and must not override one it has (0030D6). The
// prefixes are fixtures - 00D478 is in no real registry.
const NMAP = `# generated with make-mac-prefixes.pl
0030D6 MSC Vertriebs Gmbh
70B3D5 IEEE Registration Authority
70B3D5ABC Fine Grained Corp
02AABB Should Never Match
`;
const CSV = `Registry,Assignment,Organization Name,Organization Address
MA-L,00D478,"Cisco Systems, Inc",80 West Tasman Drive San Jose CA US 94568
MA-L,0030D6,"MSC Vertriebs GmbH (long name)","Industriestr. 16
Stutensee  DE 76297 "
`;

describe("MAC vendor registry", () => {
  let server: http.Server;
  let urls: { nmap: string; ieee: string };
  let nmapBody = NMAP;
  let agent: TestAgent;

  beforeAll(async () => {
    server = http.createServer((req, res) =>
      res.writeHead(200, { "Content-Type": "text/plain" }).end(req.url === "/nmap" ? nmapBody : CSV)
    );
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    urls = { nmap: `${base}/nmap`, ieee: `${base}/oui.csv` };
    agent = await createTestAgent("it-oui");
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    server.close();
    await closeDb();
  });

  it("syncs the registry and names derived MACs from it", async () => {
    expect(await syncMacOui(urls, 1)).toEqual({ entries: 5, fromIeee: 1 });
    const insert = (ip: string, values: Record<string, string | null>) =>
      db.insertInto("hosts").values({ ip, scanner_agent_id: agent.id, ...values } as never).returning("id").executeTakeFirstOrThrow();
    const cisco = await insert("198.51.100.10", { derived_mac_address: "00:D4:78:9B:C0:C7", derived_mac_source: "snmp-engine-id" });
    const ups = await insert("198.51.100.11", { mac_address: "00:30:D6:39:36:16" });
    const local = await insert("198.51.100.12", { derived_mac_address: "02:AA:BB:00:00:01", derived_mac_source: "nbstat" });
    const named = await insert("198.51.100.13", { mac_address: "00:D4:78:00:00:01", mac_vendor: "Already Named" });
    const fine = await insert("198.51.100.14", { derived_mac_address: "70:B3:D5:AB:CD:EF", derived_mac_source: "snmp-interfaces" });

    await fillMacVendors(agent.id);
    const rows = await db
      .selectFrom("hosts")
      .select(["id", "mac_vendor", "derived_mac_vendor"])
      .where("scanner_agent_id", "=", agent.id)
      .execute();
    const by = new Map(rows.map((r) => [r.id, r]));
    expect(by.get(cisco.id)?.derived_mac_vendor).toBe("Cisco Systems, Inc");
    // nmap's short name, not the IEEE's long one.
    expect(by.get(ups.id)?.mac_vendor).toBe("MSC Vertriebs Gmbh");
    // The 36-bit block's owner, not the 24-bit block it sits in.
    expect(by.get(fine.id)?.derived_mac_vendor).toBe("Fine Grained Corp");
    // Locally administered: its prefix belongs to nobody.
    expect(by.get(local.id)?.derived_mac_vendor).toBeNull();
    // A vendor nmap already named is never overwritten.
    expect(by.get(named.id)?.mac_vendor).toBe("Already Named");

    // The manufacturer filter and facet see the derived vendor too.
    const admin = await createTestUser("admin");
    try {
      const client = await loginAs(admin.username, admin.password);
      // The comma inside the name is escaped, so it stays one value.
      const list = await client.get(`/api/hosts?macVendor=${encodeURIComponent("Cisco Systems\\, Inc")}&scannerAgentId=${agent.id}`);
      const ips = list.body.items.map((h: { ip: string }) => h.ip);
      expect(ips).toContain("198.51.100.10");
      expect(ips).not.toContain("198.51.100.13");
      // And negated, it is excluded as a whole.
      const negated = await client.get(`/api/hosts?macVendor=${encodeURIComponent("-Cisco Systems\\, Inc")}&scannerAgentId=${agent.id}`);
      expect(negated.body.items.map((h: { ip: string }) => h.ip)).not.toContain("198.51.100.10");
      const facets = await client.get(`/api/hosts/facets?scannerAgentId=${agent.id}`);
      const cisco = facets.body.macVendors.find((m: { macVendor: string }) => m.macVendor === "Cisco Systems, Inc");
      expect(cisco?.count).toBe(1);
    } finally {
      await deleteTestUser(admin.id);
    }
  });

  it("keeps the table when a download is truncated", async () => {
    nmapBody = "# empty\n";
    await expect(syncMacOui(urls, 1)).rejects.toThrow(/not replacing/);
    expect((await db.selectFrom("mac_oui").select("prefix").execute()).length).toBe(5);
    const state = await db.selectFrom("mac_oui_state").selectAll().executeTakeFirstOrThrow();
    expect(state.last_error).toMatch(/not replacing/);
    nmapBody = NMAP;
  });
});
