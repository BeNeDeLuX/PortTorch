import { FormEvent, useEffect, useState } from "react";
import { api, Me, ScannerAgent, TwoFactorSetup } from "../api";
import { IconCheck, IconRefresh, IconSave, IconWarning, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { applyTheme } from "../lib/theme";
import { applyAccent } from "../lib/accent";

// Node/browser both ship the same Intl engine, so this is the same list
// PATCH /auth/preferences validates server-side (auth/routes.ts's
// VALID_TIMEZONES) - no separately-maintained list to drift out of sync.
// "UTC" is prepended explicitly: supportedValuesOf("timeZone") only
// enumerates canonical IANA identifiers and doesn't include "UTC" itself
// (confirmed by testing), even though Intl.DateTimeFormat accepts it fine
// as a timeZone value - and it's likely the most-requested single option
// for this kind of tool, so it shouldn't be missing from the list.
const TIMEZONES: string[] = (() => {
  try {
    return ["UTC", ...Intl.supportedValuesOf("timeZone")];
  } catch {
    return ["UTC"];
  }
})();

export default function Account({
  me,
  onLogout,
  onMeRefresh,
}: {
  me: Me;
  onLogout: () => void;
  // Re-fetches /auth/me into App.tsx's own `me` state - needed here
  // specifically because completing 2FA setup can flip
  // me.totpSetupRequired from true to false, which App.tsx's route
  // gating (routeElement) reads on every navigation; without this, the
  // in-memory `me` object would stay stale until the next full page
  // load/login (the existing behavior for every other preference on this
  // page), leaving someone who just complied stuck being redirected back
  // to this same page.
  onMeRefresh: () => void;
}) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<TwoFactorSetup | null>(null);
  const [setupCode, setSetupCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disablePassword, setDisablePassword] = useState("");
  const [regenerateCode, setRegenerateCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [repeatPassword, setRepeatPassword] = useState("");
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwDone, setPwDone] = useState(false);
  const [pwBusy, setPwBusy] = useState(false);

  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  // "" stands in for "no override" throughout this form (theme, page size,
  // default scanner) - translated to/from null at the API boundary, since
  // a plain <select>/<input> can't represent null directly.
  const [themePref, setThemePref] = useState(me.preferences.theme ?? "");
  const [pageSizePref, setPageSizePref] = useState(
    me.preferences.hostsPageSize ? String(me.preferences.hostsPageSize) : ""
  );
  const [showBannerPref, setShowBannerPref] = useState(me.preferences.showActiveScansBanner);
  const [defaultScannerPref, setDefaultScannerPref] = useState(me.preferences.defaultScannerAgentId ?? "");
  const [timezonePref, setTimezonePref] = useState(me.preferences.timezone ?? "");
  const [timeFormatPref, setTimeFormatPref] = useState(me.preferences.timeFormat ?? "");
  const [accentColorPref, setAccentColorPref] = useState(me.preferences.accentColor ?? "");
  const [prefsSaved, setPrefsSaved] = useState(false);
  const [prefsError, setPrefsError] = useState<string | null>(null);

  useEffect(() => {
    api.twoFactorStatus().then((s) => setEnabled(s.enabled));
    api.agents().then(setAgents).catch(() => setAgents([]));
  }, []);

  async function handleSavePreferences(e: FormEvent) {
    e.preventDefault();
    setPrefsError(null);
    setPrefsSaved(false);
    const theme = themePref ? (themePref as "dark" | "light") : null;
    const accentColor = accentColorPref ? (accentColorPref as "green" | "orange" | "blue") : null;
    try {
      await api.updatePreferences({
        theme,
        hostsPageSize: pageSizePref ? Number(pageSizePref) : null,
        showActiveScansBanner: showBannerPref,
        defaultScannerAgentId: defaultScannerPref || null,
        timezone: timezonePref || null,
        timeFormat: timeFormatPref ? (timeFormatPref as "h12" | "h24") : null,
        accentColor,
      });
      // Applies immediately to this browser too, same as the quick
      // toggle - only when a concrete theme was actually chosen here;
      // picking "Browser default" doesn't change whatever's active right
      // now, it only stops seeding a default for a future new browser.
      if (theme) {
        applyTheme(theme);
      }
      // Unlike theme, accent color has no "browser default" concept -
      // "" just means the explicit default (orange), so it always applies
      // immediately rather than being a no-op sentinel.
      applyAccent(accentColor ?? "orange");
      setPrefsSaved(true);
    } catch (err) {
      setPrefsError(err instanceof Error ? err.message : "Failed to save preferences");
    }
  }

  // The repeat field is checked here and nowhere else on purpose: it's a
  // typo guard for the person typing, not a security property, so the
  // server has no reason to know about it.
  async function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    setPwError(null);
    setPwDone(false);
    if (newPassword !== repeatPassword) {
      setPwError("The two new passwords don't match.");
      return;
    }
    setPwBusy(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setRepeatPassword("");
      setPwDone(true);
    } catch (err) {
      setPwError(err instanceof Error ? err.message : "Failed to change password");
    } finally {
      setPwBusy(false);
    }
  }

  async function handleStartSetup() {
    setError(null);
    try {
      setSetup(await api.twoFactorSetup());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start 2FA setup");
    }
  }

  async function handleConfirmSetup(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await api.twoFactorConfirm(setupCode.trim());
      setRecoveryCodes(result.recoveryCodes);
      setSetup(null);
      setSetupCode("");
      setEnabled(true);
      onMeRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
    }
  }

  async function handleDisable(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.twoFactorDisable(disablePassword);
      setDisablePassword("");
      setEnabled(false);
      setRecoveryCodes(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable 2FA");
    }
  }

  async function handleRegenerate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await api.regenerateRecoveryCodes(regenerateCode.trim());
      setRecoveryCodes(result.recoveryCodes);
      setRegenerateCode("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
    }
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Account</h2>
      <p className="empty">
        Signed in as <strong>{me.username}</strong> ({me.role}).
      </p>

      {me.totpSetupRequired && (
        <div className="callout-danger">
          <IconWarning /> Your administrator requires 2FA on every admin account. Set it up below to continue using
          the rest of PortTorch - until then, this page is the only one you can reach.
        </div>
      )}

      <h3>Preferences</h3>
      <p className="empty">
        Saved to your account, so they follow you across browsers/devices - unlike the
        quick theme toggle or table column choices in the header, which stay per-browser.
      </p>
      {prefsError && <p className="error">{prefsError}</p>}
      {prefsSaved && <p className="empty">Preferences saved.</p>}
      <form className="login-card" onSubmit={handleSavePreferences} style={{ maxWidth: 420 }}>
        <label>
          Theme
          <select value={themePref} onChange={(e) => setThemePref(e.target.value)}>
            <option value="">Browser default</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </label>
        <label>
          Accent color
          <select value={accentColorPref} onChange={(e) => setAccentColorPref(e.target.value)}>
            <option value="">Orange (default)</option>
            <option value="green">Green</option>
            <option value="blue">Blue</option>
          </select>
        </label>
        <label>
          Hosts per page (main dashboard)
          <select value={pageSizePref} onChange={(e) => setPageSizePref(e.target.value)}>
            <option value="">Default (50)</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </label>
        <label>
          Default scanner (main dashboard)
          <select value={defaultScannerPref} onChange={(e) => setDefaultScannerPref(e.target.value)}>
            <option value="">All Scanner</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={showBannerPref}
            onChange={(e) => setShowBannerPref(e.target.checked)}
          />
          {" "}Show the "Active scans" banner on the main dashboard
        </label>
        <label>
          Timezone (all dates/times throughout the dashboard)
          <select value={timezonePref} onChange={(e) => setTimezonePref(e.target.value)}>
            <option value="">Browser default</option>
            {TIMEZONES.map((tz) => (
              <option key={tz} value={tz}>
                {tz}
              </option>
            ))}
          </select>
        </label>
        <label>
          Time format
          <select value={timeFormatPref} onChange={(e) => setTimeFormatPref(e.target.value)}>
            <option value="">Browser/locale default</option>
            <option value="h12">12-hour (1:30 PM)</option>
            <option value="h24">24-hour (13:30)</option>
          </select>
        </label>
        <button type="submit" className="btn-icon-label">
          <IconSave /> Save preferences
        </button>
      </form>

      <h3>Password</h3>
      <p className="host-meta">
        Changing your password requires your current one - being signed in isn't on its own proof of who's at the
        keyboard. Other sessions you may have open elsewhere stay signed in; sign out there separately if that matters.
      </p>
      {pwError && <p className="error">{pwError}</p>}
      {pwDone && <p className="callout-success">Password changed.</p>}
      <form className="inline-form" onSubmit={handleChangePassword}>
        <input
          type="password"
          autoComplete="current-password"
          placeholder="Current password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
        />
        <input
          type="password"
          autoComplete="new-password"
          placeholder="New password (min. 8 characters)"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
        <input
          type="password"
          autoComplete="new-password"
          placeholder="Repeat new password"
          value={repeatPassword}
          onChange={(e) => setRepeatPassword(e.target.value)}
        />
        <button type="submit" className="btn-icon-label" disabled={pwBusy}>
          <IconSave /> Change password
        </button>
      </form>

      <h3>Two-Factor Authentication</h3>
      {error && <p className="error">{error}</p>}

      {recoveryCodes && (
        <div className="callout">
          <strong>Save these recovery codes</strong> - each works once, and this is the only
          time they're shown. Use one to log in if you lose access to your authenticator app.
          <pre className="key-reveal">{recoveryCodes.join("\n")}</pre>
          <button className="btn-icon-label" onClick={() => setRecoveryCodes(null)}>
            <IconCheck /> Got it
          </button>
        </div>
      )}

      {enabled === null ? (
        <p>Loading...</p>
      ) : enabled ? (
        <>
          <p className="empty">2FA is enabled on your account.</p>

          <h4>Regenerate recovery codes</h4>
          <p className="empty">Invalidates your existing recovery codes and issues a new set.</p>
          <form className="inline-form" onSubmit={handleRegenerate}>
            <input
              placeholder="6-digit code"
              value={regenerateCode}
              onChange={(e) => setRegenerateCode(e.target.value)}
              inputMode="numeric"
            />
            <button type="submit" className="btn-icon-label">
              <IconRefresh /> Regenerate
            </button>
          </form>

          <h4>Disable 2FA</h4>
          <form className="inline-form" onSubmit={handleDisable}>
            <input
              type="password"
              placeholder="Current password"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
            />
            <button type="submit" className="btn-icon-label">
              <IconX /> Disable
            </button>
          </form>
        </>
      ) : setup ? (
        <form className="login-card" onSubmit={handleConfirmSetup} style={{ maxWidth: 360 }}>
          <p>Scan this with your authenticator app (Google Authenticator, 1Password, etc.):</p>
          <img src={setup.qrCodeDataUrl} alt="2FA setup QR code" width={200} height={200} />
          <p className="empty">
            Can't scan it? Enter this secret manually: <code>{setup.secret}</code>
          </p>
          <label>
            Enter the 6-digit code to confirm
            <input
              value={setupCode}
              onChange={(e) => setSetupCode(e.target.value)}
              autoFocus
              inputMode="numeric"
            />
          </label>
          <button type="submit" className="btn-icon-label">
            <IconCheck /> Confirm
          </button>
          <button type="button" className="link-button btn-icon-label" onClick={() => setSetup(null)}>
            <IconX /> cancel
          </button>
        </form>
      ) : (
        <>
          <p className="empty">
            2FA is not enabled. Enabling it requires an authenticator app (Google Authenticator,
            1Password, Authy, etc.) on your phone.
          </p>
          <button className="btn-icon-label" onClick={handleStartSetup}>
            <IconCheck /> Enable 2FA
          </button>
        </>
      )}
    </div>
  );
}
