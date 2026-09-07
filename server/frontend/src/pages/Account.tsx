import { useEffect, useState } from "react";
import { Me, ScannerAgent, UserPreferences, api } from "../api";
import { IconWarning } from "../components/icons";
import PageHeader from "../components/PageHeader";
import AppearanceCard from "./account/AppearanceCard";
import DashboardCard from "./account/DashboardCard";
import DateTimeCard from "./account/DateTimeCard";
import PasswordCard from "./account/PasswordCard";
import SessionsCard from "./account/SessionsCard";
import TwoFactorCard from "./account/TwoFactorCard";

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

// The layout shell, and nothing else - each setting lives in its own card
// under pages/account/, next to the state it owns. This page had grown
// the same shape the Settings page did before it was split up: four
// sections and two dozen useState calls in one component, in a flat
// column where seven unrelated preferences shared a single Save button.
//
// Splitting them is not only cosmetic here. PATCH /auth/preferences
// decides per field on `"field" in body`, so a card can send its own two
// fields and leave the rest untouched - which means changing your
// timezone no longer re-submits your accent colour as a side effect.
export default function Account({
  me,
  onLogout,
  onMeRefresh,
}: {
  me: Me;
  onLogout: () => void;
  onMeRefresh: () => void;
}) {
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  // The one genuinely shared piece of state: every preference card gets
  // the whole updated object back from its PATCH, and handing it down
  // keeps the others consistent rather than each holding a drifting copy.
  const [preferences, setPreferences] = useState<UserPreferences>(me.preferences);

  useEffect(() => {
    setPreferences(me.preferences);
  }, [me.preferences]);

  useEffect(() => {
    api
      .agents()
      .then(setAgents)
      .catch(() => setAgents([]));
  }, []);

  // Also refreshes App.tsx's own copy of `me`, which it otherwise holds
  // from sign-in onwards. Without this, navigating away and back
  // re-seeds these cards from the stale copy, so a value that *is* saved
  // comes back marked "unsaved" - a documented pre-existing quirk that
  // the per-card dirty markers would have turned into a visible one.
  function handleSaved(next: UserPreferences) {
    setPreferences(next);
    onMeRefresh();
  }

  const withPrefs: Me = { ...me, preferences };

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Account</h2>
      <p className="host-meta">
        Signed in as <strong>{me.username}</strong> ({me.role}).
      </p>

      {me.totpSetupRequired && (
        <div className="callout-danger">
          <IconWarning /> Your administrator requires 2FA on every admin account. Set it up below to continue using
          the rest of PortTorch - until then, this page is the only one you can reach.
        </div>
      )}

      <section>
        <h3 className="settings-group-title">Preferences</h3>
        <p className="host-meta">
          Saved to your account, so they follow you across browsers and devices - unlike the quick theme toggle or
          the table column choices in the header, which stay per-browser.
        </p>
        <div className="settings-grid">
          <AppearanceCard me={withPrefs} onSaved={handleSaved} />
          <DashboardCard me={withPrefs} agents={agents} onSaved={handleSaved} />
          <DateTimeCard me={withPrefs} timezones={TIMEZONES} onSaved={handleSaved} />
        </div>
      </section>

      <section>
        <h3 className="settings-group-title">Security</h3>
        <div className="settings-grid">
          <PasswordCard />
          <SessionsCard />
          {/* Wide: the setup step pairs a QR code with its instructions,
              and the enabled state holds two separate forms. */}
          <div className="settings-grid-wide">
            <TwoFactorCard onMeRefresh={onMeRefresh} />
          </div>
        </div>
      </section>
    </div>
  );
}
