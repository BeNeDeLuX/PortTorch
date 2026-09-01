import fs from "fs";
import https from "https";
import os from "os";
import path from "path";
import forge from "node-forge";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { attemptDelivery } from "../../src/webhooks/dispatch";
import { resetCaBundle } from "../../src/settings/caCertificates";
import { closeDb, createTestUser, deleteTestUser, loginAs, type TestUser } from "./helpers";

// A private CA and a server certificate it signed, so the delivery path
// can be exercised against a target that is genuinely untrusted until the
// CA is uploaded - which is the whole point.
function makePki() {
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const ca = forge.pki.createCertificate();
  ca.publicKey = caKeys.publicKey;
  ca.serialNumber = "01";
  ca.validity.notBefore = new Date(Date.now() - 60_000);
  ca.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  const caAttrs = [{ name: "commonName", value: "it Webhook CA" }];
  ca.setSubject(caAttrs);
  ca.setIssuer(caAttrs);
  ca.setExtensions([{ name: "basicConstraints", cA: true }]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());

  const srvKeys = forge.pki.rsa.generateKeyPair(2048);
  const srv = forge.pki.createCertificate();
  srv.publicKey = srvKeys.publicKey;
  srv.serialNumber = "02";
  srv.validity.notBefore = new Date(Date.now() - 60_000);
  srv.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  srv.setSubject([{ name: "commonName", value: "localhost" }]);
  srv.setIssuer(caAttrs);
  srv.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }, { type: 7, ip: "127.0.0.1" }] },
  ]);
  srv.sign(caKeys.privateKey, forge.md.sha256.create());

  return {
    caPem: forge.pki.certificateToPem(ca),
    serverCert: forge.pki.certificateToPem(srv),
    serverKey: forge.pki.privateKeyToPem(srvKeys.privateKey),
  };
}

describe("webhook delivery over TLS, and editing a channel", () => {
  let admin: TestUser;
  let server: https.Server;
  let targetUrl: string;
  let received = 0;
  const pki = makePki();
  const hookIds: string[] = [];
  let tmpDir: string;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "it-webhook-tls-"));
    server = https.createServer({ key: pki.serverKey, cert: pki.serverCert }, (req, res) => {
      received += 1;
      req.resume();
      res.writeHead(200).end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    targetUrl = `https://127.0.0.1:${(server.address() as { port: number }).port}/hook`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
    await db.deleteFrom("webhooks").where("id", "in", hookIds.length ? hookIds : ["00000000-0000-0000-0000-000000000000"]).execute();
    await db.deleteFrom("trusted_ca_certificates").where("name", "=", "it-webhook-ca").execute();
    resetCaBundle();
    await deleteTestUser(admin.id);
    await closeDb();
  });

  const target = (verifyTls: boolean) => ({
    id: "00000000-0000-0000-0000-000000000000",
    channel_type: "webhook",
    url: targetUrl,
    email_to: null,
    verify_tls: verifyTls,
  });

  it("refuses a target signed by an unknown CA", async () => {
    // The state a self-hosted alert endpoint starts in.
    const outcome = await attemptDelivery(target(true), "host.new", "hello", {});
    expect(outcome.ok).toBe(false);
    expect(String(outcome.error)).toMatch(/self.signed|unable to verify/i);
    // A TLS failure has no HTTP status, so it must be treated as
    // transient and retried rather than dropped as a permanent refusal.
    expect(outcome.permanent).toBe(false);
  });

  it("delivers when verification is switched off for that channel", async () => {
    const before = received;
    const outcome = await attemptDelivery(target(false), "host.new", "hello", {});
    expect(outcome.ok).toBe(true);
    expect(received).toBe(before + 1);
  });

  it("delivers with verification on once the CA is uploaded", async () => {
    // The better answer, and the reason the CA store exists.
    const client = await loginAs(admin.username, admin.password);
    const upload = await client.post("/api/settings/ca-certificates").send({ name: "it-webhook-ca", pem: pki.caPem });
    expect(upload.status).toBe(201);

    const before = received;
    const outcome = await attemptDelivery(target(true), "host.new", "hello", {});
    expect(outcome.ok).toBe(true);
    expect(received).toBe(before + 1);
  });

  it("edits a channel in place instead of forcing a delete and recreate", async () => {
    const client = await loginAs(admin.username, admin.password);
    const created = await client.post("/api/webhooks").send({
      name: "it-edit",
      channelType: "webhook",
      url: "http://127.0.0.1:9/one",
      events: ["host.new"],
      filterTags: ["prod"],
      minSeverity: "high",
    });
    expect(created.status).toBe(201);
    hookIds.push(created.body.id);

    const patched = await client.patch(`/api/webhooks/${created.body.id}`).send({
      url: "http://127.0.0.1:9/two",
      events: ["host.new", "port.opened"],
      filterTags: ["dmz"],
      verifyTls: false,
    });
    expect(patched.status).toBe(200);
    expect(patched.body.url).toBe("http://127.0.0.1:9/two");
    expect(patched.body.events.sort()).toEqual(["host.new", "port.opened"]);
    expect(patched.body.filter_tags).toEqual(["dmz"]);
    expect(patched.body.verify_tls).toBe(false);
    // Untouched fields keep their values - this is a partial update.
    expect(patched.body.min_severity).toBe("high");
    expect(patched.body.name).toBe("it-edit");
  });

  it("clears the severity floor only when null is sent explicitly", async () => {
    // Omitted and null have to stay distinguishable, or a floor could
    // never be removed once set.
    const client = await loginAs(admin.username, admin.password);
    const id = hookIds[0];

    const untouched = await client.patch(`/api/webhooks/${id}`).send({ name: "it-edit-renamed" });
    expect(untouched.body.min_severity).toBe("high");

    const cleared = await client.patch(`/api/webhooks/${id}`).send({ minSeverity: null });
    expect(cleared.body.min_severity).toBeNull();
  });

  it("still accepts the enable/disable-only call it always took", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.patch(`/api/webhooks/${hookIds[0]}`).send({ enabled: false });
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
  });

  it("rejects an empty patch rather than reporting a no-op as success", async () => {
    const client = await loginAs(admin.username, admin.password);
    expect((await client.patch(`/api/webhooks/${hookIds[0]}`).send({})).status).toBe(400);
  });
});
