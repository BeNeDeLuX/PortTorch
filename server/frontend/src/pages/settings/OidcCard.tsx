import { FormEvent, useEffect, useState } from "react";
import { api, OidcSettings } from "../../api";
import { IconRefresh, IconSave } from "../../components/icons";
import SettingsCard from "../../components/SettingsCard";

const splitGroups = (v: string) =>
  v
    .split(/[,\n]/)
    .map((g) => g.trim())
    .filter(Boolean);

// Single sign-on through an OpenID Connect provider - Entra ID, Keycloak,
// Authentik, Okta. Loads its own settings rather than riding on the shared
// AppSettings object, since the provider is saved and tested as a unit.
export default function OidcCard() {
  const [settings, setSettings] = useState<OidcSettings | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [issuerUrl, setIssuerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  // Never prefilled: the API does not return the stored secret, so blank
  // means "keep it", the same as the SMTP password.
  const [clientSecret, setClientSecret] = useState("");
  const [redirectUri, setRedirectUri] = useState("");
  const [scopes, setScopes] = useState("");
  const [usernameClaim, setUsernameClaim] = useState("");
  const [groupsClaim, setGroupsClaim] = useState("");
  const [adminGroups, setAdminGroups] = useState("");
  const [operatorGroups, setOperatorGroups] = useState("");
  const [userGroups, setUserGroups] = useState("");
  const [defaultRole, setDefaultRole] = useState<"" | "user" | "operator">("");
  const [buttonLabel, setButtonLabel] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  function fill(s: OidcSettings) {
    setSettings(s);
    setEnabled(s.enabled);
    setIssuerUrl(s.issuerUrl ?? "");
    setClientId(s.clientId ?? "");
    // The address this page is served from is the usual answer, and a
    // reverse proxy is the only reason it would differ - so it is offered
    // rather than left for the admin to construct by hand.
    setRedirectUri(s.redirectUri ?? `${window.location.origin}/auth/oidc/callback`);
    setScopes(s.scopes);
    setUsernameClaim(s.usernameClaim);
    setGroupsClaim(s.groupsClaim);
    setAdminGroups(s.adminGroups.join(", "));
    setOperatorGroups(s.operatorGroups.join(", "));
    setUserGroups(s.userGroups.join(", "));
    setDefaultRole(s.defaultRole ?? "");
    setButtonLabel(s.buttonLabel);
  }

  useEffect(() => {
    api
      .oidcSettings()
      .then(fill)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load single sign-on settings"));
  }, []);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      fill(
        await api.updateOidcSettings({
          enabled,
          issuerUrl: issuerUrl.trim() || null,
          clientId: clientId.trim() || null,
          ...(clientSecret ? { clientSecret } : {}),
          redirectUri: redirectUri.trim() || null,
          scopes: scopes.trim(),
          usernameClaim: usernameClaim.trim(),
          groupsClaim: groupsClaim.trim(),
          adminGroups: splitGroups(adminGroups),
          operatorGroups: splitGroups(operatorGroups),
          userGroups: splitGroups(userGroups),
          defaultRole: defaultRole || null,
          buttonLabel: buttonLabel.trim(),
        })
      );
      setClientSecret("");
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save single sign-on settings");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTestResult(null);
    setTesting(true);
    try {
      const r = await api.testOidc();
      setTestResult(
        r.ok
          ? `Reached ${r.issuer}. Sign-in goes to ${r.authorizationEndpoint ?? "?"}.`
          : `Failed: ${r.error}`
      );
    } catch (err) {
      setTestResult(err instanceof Error ? err.message : "Test failed");
    } finally {
      setTesting(false);
    }
  }

  return (
    <SettingsCard
      title="Single sign-on (OpenID Connect)"
      description={
        <>
          Lets people sign in with their company account through Entra ID, Keycloak, Authentik, Okta or any other OpenID
          Connect provider. Register PortTorch there as a confidential web application with the redirect URI below. The
          role comes from the provider's groups and is re-read at every sign-in, so removing someone from a group takes
          effect the next time they log in. Accounts are created on first sign-in. An existing local account with the
          same name is never taken over. Local logins keep working, so an admin can always get in if the provider is
          down. The provider is reached through the configured proxy and trusts the uploaded CA certificates.
        </>
      }
      error={error}
      notice={saved && <p className="callout-success">Single sign-on settings saved.</p>}
    >
      {settings && (
        <form className="settings-form" onSubmit={handleSave}>
          <label className="hide-empty-toggle">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Offer single sign-on on the login page
          </label>
          <label>
            Issuer URL
            <input
              placeholder="https://login.microsoftonline.com/<tenant>/v2.0"
              value={issuerUrl}
              onChange={(e) => setIssuerUrl(e.target.value)}
            />
          </label>
          <label>
            Client ID
            <input autoComplete="off" value={clientId} onChange={(e) => setClientId(e.target.value)} />
          </label>
          <label>
            Client secret
            <input
              type="password"
              autoComplete="new-password"
              placeholder={settings.clientSecretSet ? "unchanged - type to replace" : "no secret stored"}
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
            />
          </label>
          <label>
            Redirect URI
            <input value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} />
          </label>
          <label>
            Scopes
            <input value={scopes} onChange={(e) => setScopes(e.target.value)} />
          </label>
          <label>
            Username claim
            <input placeholder="preferred_username" value={usernameClaim} onChange={(e) => setUsernameClaim(e.target.value)} />
          </label>
          <label>
            Groups claim
            <input
              placeholder="groups, or realm_access.roles for Keycloak roles"
              value={groupsClaim}
              onChange={(e) => setGroupsClaim(e.target.value)}
            />
          </label>
          <label>
            Admin groups
            <input placeholder="comma-separated" value={adminGroups} onChange={(e) => setAdminGroups(e.target.value)} />
          </label>
          <label>
            Operator groups
            <input placeholder="comma-separated" value={operatorGroups} onChange={(e) => setOperatorGroups(e.target.value)} />
          </label>
          <label>
            User groups
            <input placeholder="comma-separated" value={userGroups} onChange={(e) => setUserGroups(e.target.value)} />
          </label>
          <label>
            Anyone in none of these groups
            <select value={defaultRole} onChange={(e) => setDefaultRole(e.target.value as "" | "user" | "operator")}>
              <option value="">is refused</option>
              <option value="user">gets the user role (read-only)</option>
              <option value="operator">gets the operator role</option>
            </select>
          </label>
          <label>
            Button label
            <input value={buttonLabel} onChange={(e) => setButtonLabel(e.target.value)} />
          </label>
          <p className="host-meta settings-form-actions">
            Entra ID sends group object IDs, not names, unless the app registration is set to emit names - enter whatever
            your provider actually puts in the groups claim.
            {settings.missing.length > 0 && ` Still missing before it can be turned on: ${settings.missing.join(", ")}.`}
          </p>
          <div className="inline-actions settings-form-actions">
            <button type="submit" className="btn-icon-label" disabled={saving}>
              <IconSave /> {saving ? "Saving..." : "Save single sign-on"}
            </button>
            <button type="button" className="btn-icon-label" onClick={handleTest} disabled={testing}>
              <IconRefresh /> {testing ? "Testing..." : "Test connection"}
            </button>
          </div>
        </form>
      )}
      {testResult && <p className="settings-state">{testResult}</p>}
    </SettingsCard>
  );
}
