import * as client from "openid-client";
import { db } from "../db";
import { outboundFetch } from "../lib/outbound";
import { caBundle } from "../settings/caCertificates";

// Single sign-on over OpenID Connect: the authorization code flow with
// PKCE, a state and a nonce, verified by openid-client rather than by hand
// - unlike TOTP, ID token validation is the kind of code where a small
// mistake is a full authentication bypass, and a maintained library that
// does only this is the better trade.

export type Role = "admin" | "operator" | "user";

export interface OidcSettings {
  enabled: boolean;
  issuerUrl: string | null;
  clientId: string | null;
  clientSecret: string | null;
  redirectUri: string | null;
  scopes: string;
  usernameClaim: string;
  groupsClaim: string;
  adminGroups: string[];
  operatorGroups: string[];
  userGroups: string[];
  defaultRole: "user" | "operator" | null;
  buttonLabel: string;
  // Provider groups -> scanners their members may see. Empty means scanner
  // access stays the manually assigned one.
  scannerGroups: ScannerGroupMapping[];
  scannerUnmatched: "all" | "deny";
}

export interface ScannerGroupMapping {
  group: string;
  scannerAgentIds: string[];
}

// Same "omitted keeps the stored one" rule as the SMTP password and the
// HEC token: the form cannot prefill a secret the API never returns.
export type OidcSettingsInput = Omit<OidcSettings, "clientSecret"> & { clientSecret?: string | null };

export async function getOidcSettings(): Promise<OidcSettings> {
  const r = await db
    .selectFrom("app_settings")
    .select([
      "oidc_enabled",
      "oidc_issuer_url",
      "oidc_client_id",
      "oidc_client_secret",
      "oidc_redirect_uri",
      "oidc_scopes",
      "oidc_username_claim",
      "oidc_groups_claim",
      "oidc_admin_groups",
      "oidc_operator_groups",
      "oidc_user_groups",
      "oidc_default_role",
      "oidc_button_label",
      "oidc_scanner_unmatched",
    ])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  const mappingRows = await db
    .selectFrom("oidc_scanner_groups")
    .select(["group_name", "scanner_agent_id"])
    .orderBy("group_name")
    .execute();
  const byGroup = new Map<string, string[]>();
  for (const m of mappingRows) byGroup.set(m.group_name, [...(byGroup.get(m.group_name) ?? []), m.scanner_agent_id]);
  return {
    enabled: r.oidc_enabled,
    issuerUrl: r.oidc_issuer_url,
    clientId: r.oidc_client_id,
    clientSecret: r.oidc_client_secret,
    redirectUri: r.oidc_redirect_uri,
    scopes: r.oidc_scopes,
    usernameClaim: r.oidc_username_claim,
    groupsClaim: r.oidc_groups_claim,
    adminGroups: r.oidc_admin_groups,
    operatorGroups: r.oidc_operator_groups,
    userGroups: r.oidc_user_groups,
    defaultRole: r.oidc_default_role,
    buttonLabel: r.oidc_button_label,
    scannerGroups: [...byGroup].map(([group, scannerAgentIds]) => ({ group, scannerAgentIds })),
    scannerUnmatched: r.oidc_scanner_unmatched,
  };
}

export async function setOidcSettings(input: OidcSettingsInput): Promise<void> {
  // Replaced as a whole, in one transaction with the settings row, so a
  // sign-in never sees half of an edit.
  await db.transaction().execute(async (trx) => {
    await trx.deleteFrom("oidc_scanner_groups").execute();
    const rows = input.scannerGroups.flatMap((m) =>
      [...new Set(m.scannerAgentIds)].map((id) => ({ group_name: m.group.trim().toLowerCase(), scanner_agent_id: id }))
    );
    if (rows.length > 0) {
      await trx.insertInto("oidc_scanner_groups").values(rows).onConflict((oc) => oc.doNothing()).execute();
    }
    await trx
      .updateTable("app_settings")
      .set({
        oidc_enabled: input.enabled,
        oidc_issuer_url: input.issuerUrl,
        oidc_client_id: input.clientId,
        oidc_redirect_uri: input.redirectUri,
        oidc_scopes: input.scopes,
        oidc_username_claim: input.usernameClaim,
        oidc_groups_claim: input.groupsClaim,
        oidc_admin_groups: input.adminGroups,
        oidc_operator_groups: input.operatorGroups,
        oidc_user_groups: input.userGroups,
        oidc_default_role: input.defaultRole,
        oidc_button_label: input.buttonLabel,
        oidc_scanner_unmatched: input.scannerUnmatched,
        ...(input.clientSecret === undefined ? {} : { oidc_client_secret: input.clientSecret }),
      })
      .where("id", "=", 1)
      .execute();
  });
  cached = null;
}

// Everything needed before a login can be attempted. Reported to the admin
// rather than failing obscurely at the provider.
export function missingSettings(s: OidcSettings): string[] {
  const missing: string[] = [];
  if (!s.issuerUrl) missing.push("issuer URL");
  if (!s.clientId) missing.push("client ID");
  if (!s.clientSecret) missing.push("client secret");
  if (!s.redirectUri) missing.push("redirect URI");
  return missing;
}

// Discovery is a network round trip, so its result is kept until a
// setting changes or an uploaded CA does - the cache key covers both.
let cached: { key: string; config: client.Configuration } | null = null;

export function resetOidcCache(): void {
  cached = null;
}

export async function oidcConfiguration(s: OidcSettings): Promise<client.Configuration> {
  const ca = await caBundle();
  const key = JSON.stringify([s.issuerUrl, s.clientId, s.clientSecret, ca?.length ?? 0]);
  if (cached && cached.key === key) return cached.config;

  const issuer = new URL(s.issuerUrl!);
  const config = await client.discovery(
    issuer,
    s.clientId!,
    undefined,
    client.ClientSecretPost(s.clientSecret!),
    {
      // The same transport as every other outbound call: the configured
      // proxy and the uploaded CA bundle apply, so a provider behind a
      // private CA works the same way an internal SMTP relay does.
      [client.customFetch]: (url, options) =>
        outboundFetch(url, options as RequestInit, { ca }) as ReturnType<client.CustomFetch>,
      // Plain http is refused by the library unless explicitly allowed.
      // Allowed only when the admin typed an http:// issuer - a lab
      // provider - and never silently for an https one.
      execute: issuer.protocol === "http:" ? [client.allowInsecureRequests] : [],
    }
  );
  cached = { key, config };
  return config;
}

export interface PendingLogin {
  state: string;
  nonce: string;
  codeVerifier: string;
}

export async function authorizationRedirect(s: OidcSettings): Promise<{ url: URL; pending: PendingLogin }> {
  const config = await oidcConfiguration(s);
  const pending = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier: client.randomPKCECodeVerifier(),
  };
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: s.redirectUri!,
    scope: s.scopes,
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(pending.codeVerifier),
    code_challenge_method: "S256",
  });
  return { url, pending };
}

// Reads a claim by name, or by a dotted path for providers that nest
// them - Keycloak puts realm roles under realm_access.roles.
export function readClaim(claims: Record<string, unknown>, path: string): unknown {
  let value: unknown = claims;
  for (const part of path.split(".")) {
    if (value === null || typeof value !== "object") return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

export function groupsFrom(claims: Record<string, unknown>, path: string): string[] {
  const value = readClaim(claims, path);
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  if (typeof value === "string") return value.split(/[,\s]+/).filter(Boolean);
  return [];
}

// The highest role any of the user's groups grants. Group names compare
// case-insensitively: providers disagree on case, and a role silently not
// granted because "Porttorch-Admins" is not "porttorch-admins" is the
// kind of failure nobody can diagnose from the login screen.
export function roleForGroups(groups: string[], s: Pick<OidcSettings, "adminGroups" | "operatorGroups" | "userGroups" | "defaultRole">): Role | null {
  const have = new Set(groups.map((g) => g.toLowerCase()));
  const any = (list: string[]) => list.some((g) => have.has(g.toLowerCase()));
  if (any(s.adminGroups)) return "admin";
  if (any(s.operatorGroups)) return "operator";
  if (any(s.userGroups)) return "user";
  return s.defaultRole;
}

// Which scanners an SSO user may see, from their groups. null means "leave
// the assignment alone" (no mappings configured); an empty list means "no
// restriction" (the existing convention for zero assignment rows); "deny"
// means the user is in no mapped group and unmatched users are refused.
export function scannersForGroups(
  groups: string[],
  s: Pick<OidcSettings, "scannerGroups" | "scannerUnmatched">
): string[] | null | "deny" {
  if (s.scannerGroups.length === 0) return null;
  const have = new Set(groups.map((g) => g.toLowerCase()));
  const ids = new Set<string>();
  for (const m of s.scannerGroups) {
    if (have.has(m.group.toLowerCase())) for (const id of m.scannerAgentIds) ids.add(id);
  }
  if (ids.size > 0) return [...ids].sort();
  return s.scannerUnmatched === "deny" ? "deny" : [];
}

export interface OidcIdentity {
  issuer: string;
  subject: string;
  username: string;
  groups: string[];
}

export async function completeLogin(s: OidcSettings, currentUrl: URL, pending: PendingLogin): Promise<OidcIdentity> {
  const config = await oidcConfiguration(s);
  const tokens = await client.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: pending.codeVerifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });
  const idClaims = tokens.claims();
  if (!idClaims) throw new Error("the provider returned no ID token");
  let claims: Record<string, unknown> = { ...idClaims };

  // Groups often travel only in the userinfo response (Keycloak without a
  // token mapper, many others by default), so it is consulted whenever
  // the ID token lacks the configured claim.
  if (readClaim(claims, s.groupsClaim) === undefined && config.serverMetadata().userinfo_endpoint) {
    const info = await client.fetchUserInfo(config, tokens.access_token, idClaims.sub);
    claims = { ...info, ...claims };
  }

  const name = readClaim(claims, s.usernameClaim) ?? claims.email ?? idClaims.sub;
  return {
    issuer: idClaims.iss,
    subject: idClaims.sub,
    username: String(name).trim().slice(0, 100),
    groups: groupsFrom(claims, s.groupsClaim),
  };
}
