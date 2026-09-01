import tls from "tls";
import forge from "node-forge";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { caBundle, resetCaBundle } from "../../src/settings/caCertificates";
import { closeDb, createTestUser, deleteTestUser, loginAs, type TestUser } from "./helpers";

function makeCaPem(commonName: string, notAfter = new Date("2030-01-01T00:00:00Z")): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date("2026-01-01T00:00:00Z");
  cert.validity.notAfter = notAfter;
  const attrs = [{ name: "commonName", value: commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{ name: "basicConstraints", cA: true }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

// Uploading the CA that signed an internal server's certificate is the
// better answer than switching verification off, which accepts any
// certificate at all.
describe("trusted CA certificates", () => {
  let admin: TestUser;
  let operator: TestUser;
  const uploaded: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
  });

  afterAll(async () => {
    await db.deleteFrom("trusted_ca_certificates").where("name", "like", "it-ca%").execute();
    resetCaBundle();
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  afterEach(async () => {
    if (uploaded.length) {
      await db.deleteFrom("trusted_ca_certificates").where("id", "in", uploaded).execute();
      uploaded.length = 0;
      resetCaBundle();
    }
  });

  it("is admin-only", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.post("/api/settings/ca-certificates").send({ name: "it-ca-denied", pem: makeCaPem("Denied") });
    expect(res.status).toBe(403);
  });

  it("stores a CA with the details the list needs, and never returns the PEM", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.post("/api/settings/ca-certificates").send({ name: "it-ca-one", pem: makeCaPem("it CA One") });
    expect(res.status).toBe(201);
    uploaded.push(res.body.id);
    expect(res.body.subject).toContain("CN=it CA One");
    expect(res.body.not_after).toBeTruthy();

    const list = await client.get("/api/settings/ca-certificates");
    const row = list.body.find((c: { id: string }) => c.id === res.body.id);
    expect(row.name).toBe("it-ca-one");
    // The list is a summary; several certificates of base64 would make it
    // unreadable, and the PEM is available from the source anyway.
    expect(row.pem).toBeUndefined();
  });

  it("refuses a duplicate, naming the entry that already has it", async () => {
    const client = await loginAs(admin.username, admin.password);
    const pem = makeCaPem("it CA Dup");
    const first = await client.post("/api/settings/ca-certificates").send({ name: "it-ca-dup", pem });
    expect(first.status).toBe(201);
    uploaded.push(first.body.id);

    const second = await client.post("/api/settings/ca-certificates").send({ name: "it-ca-dup-again", pem });
    expect(second.status).toBe(409);
    expect(String(second.body.error)).toContain("it-ca-dup");
  });

  it("adds uploads to the public roots rather than replacing them", async () => {
    // The trap this guards: Node's `ca` option *replaces* the default
    // trust store. Handing it only the internal CA would silently break
    // verification of every public certificate - and that failure would
    // surface somewhere unrelated to this page.
    expect(await caBundle()).toBeUndefined();

    const client = await loginAs(admin.username, admin.password);
    const res = await client.post("/api/settings/ca-certificates").send({ name: "it-ca-bundle", pem: makeCaPem("it CA Bundle") });
    expect(res.status).toBe(201);
    uploaded.push(res.body.id);

    const bundle = await caBundle();
    expect(bundle).toBeDefined();
    expect(bundle!.length).toBe(tls.rootCertificates.length + 1);
    expect(bundle).toContain(tls.rootCertificates[0]);
  });

  it("alerts once on a CA about to expire, and not again", async () => {
    // Uniquely unpleasant to miss: when a trust anchor lapses, email
    // alerting and SIEM forwarding stop at the same moment, and the only
    // previous warning was a red label on a page nobody opens.
    const { runCertificateExpiryChecks } = await import("../../src/webhooks/expiryAlerts");
    const hook = await db
      .insertInto("webhooks")
      .values({
        name: `it-ca-expiry-hook-${Date.now()}`,
        channel_type: "webhook",
        url: "http://127.0.0.1:9/never-listening",
        events: ["ca_certificate.expiring_soon"],
        enabled: true,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();

    const client = await loginAs(admin.username, admin.password);
    const soon = new Date(Date.now() + 5 * 24 * 60 * 60_000);
    const res = await client
      .post("/api/settings/ca-certificates")
      .send({ name: "it-ca-expiring", pem: makeCaPem("it CA Expiring", soon) });
    expect(res.status).toBe(201);
    uploaded.push(res.body.id);

    await runCertificateExpiryChecks();
    const deadline = Date.now() + 3000;
    let events: string[] = [];
    while (Date.now() < deadline) {
      const rows = await db.selectFrom("webhook_deliveries").select(["event"]).where("webhook_id", "=", hook.id).execute();
      events = rows.map((r) => r.event);
      if (events.length) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(events).toContain("ca_certificate.expiring_soon");

    // Fire-once: an expiry only moves one way, so a second pass must stay
    // silent rather than repeating hourly until someone acts.
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", hook.id).execute();
    await runCertificateExpiryChecks();
    await new Promise((r) => setTimeout(r, 600));
    const after = await db.selectFrom("webhook_deliveries").select(["event"]).where("webhook_id", "=", hook.id).execute();
    expect(after).toHaveLength(0);

    await db.deleteFrom("webhooks").where("id", "=", hook.id).execute();
  });

  it("stops trusting a removed certificate", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.post("/api/settings/ca-certificates").send({ name: "it-ca-gone", pem: makeCaPem("it CA Gone") });
    expect(res.status).toBe(201);
    expect((await caBundle())!.length).toBe(tls.rootCertificates.length + 1);

    expect((await client.delete(`/api/settings/ca-certificates/${res.body.id}`)).status).toBe(204);
    // Back to undefined, so Node uses its own default rather than being
    // handed a copy of it.
    expect(await caBundle()).toBeUndefined();
    expect((await client.delete(`/api/settings/ca-certificates/${res.body.id}`)).status).toBe(404);
  });
});
