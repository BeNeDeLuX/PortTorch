import crypto from "crypto";
import http from "http";
import type { AddressInfo } from "net";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, getApp, loginAs, type SessionClient, type TestUser } from "./helpers";

const CLIENT_ID = "porttorch-test";
const CLIENT_SECRET = "test-client-secret-0123456789";
const REDIRECT_URI = "https://porttorch.test/auth/oidc/callback";

interface Identity {
  sub: string;
  // Claims in the ID token.
  claims: Record<string, unknown>;
  // Claims only the userinfo endpoint returns.
  userinfo?: Record<string, unknown>;
  // Signs the ID token with this nonce instead of the one requested.
  wrongNonce?: boolean;
}

// A minimal but real OpenID provider: discovery, a JWKS, an authorization
// code bound to its PKCE challenge, signed ID tokens and userinfo. The
// library under test does all the verifying against it, so what is pinned
// here is the actual protocol exchange rather than a mock of the library.
class TestProvider {
  server!: http.Server;
  issuer = "";
  private key!: CryptoKey;
  private jwk!: Record<string, unknown>;
  private codes = new Map<string, { identity: Identity; nonce: string; challenge: string; redirectUri: string }>();
  private tokens = new Map<string, Identity>();

  async start() {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    this.key = privateKey;
    this.jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
    this.server = http.createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  // What a user's browser does at the provider: accept the authorization
  // request and come back with a code.
  authorize(authUrl: string, identity: Identity): { code: string; state: string } {
    const url = new URL(authUrl);
    const code = crypto.randomBytes(16).toString("hex");
    this.codes.set(code, {
      identity,
      nonce: url.searchParams.get("nonce")!,
      challenge: url.searchParams.get("code_challenge")!,
      redirectUri: url.searchParams.get("redirect_uri")!,
    });
    return { code, state: url.searchParams.get("state")! };
  }

  private json(res: http.ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url!, this.issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      return this.json(res, 200, {
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/authorize`,
        token_endpoint: `${this.issuer}/token`,
        userinfo_endpoint: `${this.issuer}/userinfo`,
        jwks_uri: `${this.issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (url.pathname === "/jwks") return this.json(res, 200, { keys: [this.jwk] });
    if (url.pathname === "/userinfo") {
      const identity = this.tokens.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
      if (!identity) return this.json(res, 401, { error: "invalid_token" });
      return this.json(res, 200, { sub: identity.sub, ...identity.claims, ...identity.userinfo });
    }
    if (url.pathname === "/token" && req.method === "POST") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const grant = this.codes.get(form.get("code") ?? "");
      this.codes.delete(form.get("code") ?? "");
      if (!grant || form.get("client_id") !== CLIENT_ID || form.get("client_secret") !== CLIENT_SECRET) {
        return this.json(res, 400, { error: "invalid_grant" });
      }
      const challenge = crypto.createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
      if (challenge !== grant.challenge || form.get("redirect_uri") !== grant.redirectUri) {
        return this.json(res, 400, { error: "invalid_grant" });
      }
      const accessToken = crypto.randomBytes(16).toString("hex");
      this.tokens.set(accessToken, grant.identity);
      const idToken = await new SignJWT({ ...grant.identity.claims, nonce: grant.identity.wrongNonce ? "not-the-nonce" : grant.nonce })
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(this.issuer)
        .setSubject(grant.identity.sub)
        .setAudience(CLIENT_ID)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(this.key);
      return this.json(res, 200, { access_token: accessToken, token_type: "Bearer", expires_in: 300, id_token: idToken });
    }
    this.json(res, 404, { error: "not found" });
  }
}

function sessionCookie(res: request.Response): string | null {
  const setCookie = res.headers["set-cookie"] as unknown as string[] | undefined;
  return setCookie?.length ? setCookie[0].split(";")[0] : null;
}

// Drives the whole browser round trip: start at PortTorch, "log in" at the
// provider, come back to the callback with the same session cookie.
async function ssoLogin(
  provider: TestProvider,
  identity: Identity,
  tamper?: (p: { code: string; state: string }) => { code: string; state: string }
): Promise<{ location: string; cookie: string | null; replay: () => Promise<request.Response> }> {
  const start = await request(getApp()).get("/auth/oidc/login").set("X-Forwarded-Proto", "https");
  expect(start.status).toBe(302);
  const cookie = sessionCookie(start)!;
  const params = provider.authorize(start.headers.location, identity);
  const { code, state } = tamper ? tamper(params) : params;
  const callback = () =>
    request(getApp())
      .get(`/auth/oidc/callback?code=${code}&state=${state}`)
      .set("X-Forwarded-Proto", "https")
      .set("Cookie", cookie);
  const res = await callback();
  expect(res.status).toBe(302);
  return { location: res.headers.location, cookie: sessionCookie(res), replay: callback };
}

const ssoError = (location: string) => new URL(location, "https://x").searchParams.get("sso_error");

describe("single sign-on (OIDC)", () => {
  const provider = new TestProvider();
  let admin: TestUser;
  let adminClient: SessionClient;
  let previousTotp = false;

  const settings = () => ({
    enabled: true,
    issuerUrl: provider.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    scopes: "openid profile email",
    usernameClaim: "preferred_username",
    groupsClaim: "groups",
    adminGroups: ["PortTorch-Admins"],
    operatorGroups: ["porttorch-analysts"],
    userGroups: [],
    defaultRole: null,
    buttonLabel: "Sign in with Test IdP",
  });

  beforeAll(async () => {
    await provider.start();
    admin = await createTestUser("admin");
    adminClient = await loginAs(admin.username, admin.password);
    previousTotp = (await db.selectFrom("app_settings").select("require_admin_totp").where("id", "=", 1).executeTakeFirstOrThrow()).require_admin_totp;
  });

  afterAll(async () => {
    await db.deleteFrom("users").where("auth_source", "=", "oidc").execute();
    await db
      .updateTable("app_settings")
      .set({ oidc_enabled: false, oidc_client_secret: null, oidc_issuer_url: null, require_admin_totp: previousTotp })
      .where("id", "=", 1)
      .execute();
    await deleteTestUser(admin.id);
    provider.server.close();
    await closeDb();
  });

  it("is offered on the login page only once fully configured, and keeps the secret back", async () => {
    await adminClient.put("/api/settings/oidc").send({ ...settings(), enabled: false, clientSecret: null });
    expect((await request(getApp()).get("/auth/oidc")).body.enabled).toBe(false);
    // Half-configured cannot be switched on.
    const refused = await adminClient.put("/api/settings/oidc").send({ ...settings(), clientSecret: undefined });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toContain("client secret");

    const saved = await adminClient.put("/api/settings/oidc").send(settings());
    expect(saved.status).toBe(200);
    expect(saved.body).not.toHaveProperty("clientSecret");
    expect(saved.body.clientSecretSet).toBe(true);
    expect(await request(getApp()).get("/auth/oidc").then((r) => r.body)).toEqual({ enabled: true, label: "Sign in with Test IdP" });

    // Saving again without a secret keeps the stored one.
    const resaved = await adminClient.put("/api/settings/oidc").send({ ...settings(), clientSecret: undefined });
    expect(resaved.body.clientSecretSet).toBe(true);

    const test = await adminClient.post("/api/settings/oidc/test");
    expect(test.body).toMatchObject({ ok: true, issuer: provider.issuer, tokenEndpoint: `${provider.issuer}/token` });

    // The provider is reached over the shared outbound transport, not a
    // bare fetch: a configured proxy applies to it like to every other
    // outbound call. An unreachable one makes discovery fail at the proxy.
    await db.updateTable("app_settings").set({ proxy_http_url: "http://127.0.0.1:9" }).where("id", "=", 1).execute();
    try {
      const viaProxy = await adminClient.post("/api/settings/oidc/test");
      expect(viaProxy.body.ok).toBe(false);
    } finally {
      await db.updateTable("app_settings").set({ proxy_http_url: null }).where("id", "=", 1).execute();
    }
    expect((await adminClient.post("/api/settings/oidc/test")).body.ok).toBe(true);
  });

  it("creates an account on first sign-in with the role its groups grant", async () => {
    await db.updateTable("app_settings").set({ require_admin_totp: true }).where("id", "=", 1).execute();
    const login = await ssoLogin(provider, {
      sub: "alice-1",
      claims: { preferred_username: "it-sso-alice", groups: ["porttorch-admins", "staff"] },
    });
    expect(login.location).toBe("/");
    const me = await request(getApp()).get("/auth/me").set("Cookie", login.cookie!);
    expect(me.body).toMatchObject({ username: "it-sso-alice", role: "admin", authSource: "oidc" });
    // The provider owns the second factor; the local 2FA requirement does
    // not lock an SSO admin out.
    expect(me.body.totpSetupRequired).toBe(false);

    const row = await db.selectFrom("users").selectAll().where("username", "=", "it-sso-alice").executeTakeFirstOrThrow();
    expect(row).toMatchObject({ auth_source: "oidc", oidc_subject: "alice-1", oidc_issuer: provider.issuer, password_hash: null });
  });

  it("re-reads the role from the groups at every sign-in", async () => {
    const login = await ssoLogin(provider, {
      sub: "alice-1",
      claims: { preferred_username: "it-sso-alice", groups: ["porttorch-analysts"] },
    });
    const me = await request(getApp()).get("/auth/me").set("Cookie", login.cookie!);
    expect(me.body.role).toBe("operator");
    expect(await db.selectFrom("users").select("id").where("username", "=", "it-sso-alice").execute()).toHaveLength(1);
  });

  it("takes the groups from userinfo when the ID token does not carry them", async () => {
    const login = await ssoLogin(provider, {
      sub: "bob-1",
      claims: { preferred_username: "it-sso-bob" },
      userinfo: { groups: ["porttorch-analysts"] },
    });
    const me = await request(getApp()).get("/auth/me").set("Cookie", login.cookie!);
    expect(me.body).toMatchObject({ username: "it-sso-bob", role: "operator" });
  });

  it("refuses someone in no allowed group, unless a default role is set", async () => {
    const refused = await ssoLogin(provider, { sub: "carol-1", claims: { preferred_username: "it-sso-carol", groups: ["staff"] } });
    expect(ssoError(refused.location)).toContain("not in any group");
    expect(await db.selectFrom("users").select("id").where("username", "=", "it-sso-carol").execute()).toHaveLength(0);

    await adminClient.put("/api/settings/oidc").send({ ...settings(), defaultRole: "user" });
    const allowed = await ssoLogin(provider, { sub: "carol-1", claims: { preferred_username: "it-sso-carol", groups: ["staff"] } });
    expect(allowed.location).toBe("/");
    expect((await request(getApp()).get("/auth/me").set("Cookie", allowed.cookie!)).body.role).toBe("user");
    await adminClient.put("/api/settings/oidc").send(settings());
  });

  it("never takes over a local account with the same name", async () => {
    const local = await createTestUser("user");
    try {
      const res = await ssoLogin(provider, { sub: "mallory-1", claims: { preferred_username: local.username, groups: ["porttorch-admins"] } });
      expect(ssoError(res.location)).toContain("already exists");
      const row = await db.selectFrom("users").select(["role", "auth_source"]).where("id", "=", local.id).executeTakeFirstOrThrow();
      expect(row).toEqual({ role: "user", auth_source: "local" });
    } finally {
      await deleteTestUser(local.id);
    }
  });

  it("rejects a forged state, a wrong nonce and a replayed callback", async () => {
    const identity = { sub: "dave-1", claims: { preferred_username: "it-sso-dave", groups: ["porttorch-admins"] } };
    const forged = await ssoLogin(provider, identity, (p) => ({ ...p, state: "forged" }));
    expect(ssoError(forged.location)).toContain("could not be verified");

    const nonce = await ssoLogin(provider, { ...identity, wrongNonce: true });
    expect(ssoError(nonce.location)).toContain("could not be verified");

    const ok = await ssoLogin(provider, identity);
    expect(ok.location).toBe("/");
    const replay = await ok.replay();
    expect(ssoError(replay.headers.location)).toContain("expired");
    expect(await db.selectFrom("users").select("id").where("username", "=", "it-sso-dave").execute()).toHaveLength(1);
  });

  it("gives an SSO account no local password, by any route", async () => {
    const login = await ssoLogin(provider, { sub: "erin-1", claims: { preferred_username: "it-sso-erin", groups: ["porttorch-analysts"] } });
    const user = await db.selectFrom("users").select("id").where("username", "=", "it-sso-erin").executeTakeFirstOrThrow();

    expect((await request(getApp()).post("/auth/login").set("X-Forwarded-Proto", "https").send({ username: "it-sso-erin", password: "" })).status).toBe(400);
    expect((await request(getApp()).post("/auth/login").set("X-Forwarded-Proto", "https").send({ username: "it-sso-erin", password: "anything-at-all-1" })).status).toBe(401);
    const change = await request(getApp())
      .post("/auth/password")
      .set("Cookie", login.cookie!)
      .send({ currentPassword: "x", newPassword: "A-New-Long-Password-9" });
    expect(change.status).toBe(400);
    expect((await request(getApp()).post("/auth/2fa/setup").set("Cookie", login.cookie!)).status).toBe(400);
    expect((await adminClient.post(`/api/users/${user.id}/password`).send({ password: "A-New-Long-Password-9" })).status).toBe(400);

    const listed = (await adminClient.get("/api/users")).body.find((u: { id: number }) => u.id === user.id);
    expect(listed.auth_source).toBe("oidc");
  });

  it("sends the browser back to the login page when SSO is off", async () => {
    await adminClient.put("/api/settings/oidc").send({ ...settings(), enabled: false });
    const res = await request(getApp()).get("/auth/oidc/login");
    expect(res.status).toBe(302);
    expect(ssoError(res.headers.location)).toContain("not enabled");
  });
});
