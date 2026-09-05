import { useEffect, useState } from "react";
import { api, AppSettings, Me } from "../api";
import PageHeader from "../components/PageHeader";
import AlertingCard from "./settings/AlertingCard";
import HecCard from "./settings/HecCard";
import RequireTotpCard from "./settings/RequireTotpCard";
import RetentionCard from "./settings/RetentionCard";
import ScanLogRetentionCard from "./settings/ScanLogRetentionCard";
import ScanningCard from "./settings/ScanningCard";
import SmtpCard from "./settings/SmtpCard";
import StorageCard from "./settings/StorageCard";
import TlsCertificateCard from "./settings/TlsCertificateCard";
import TrustedCaCard from "./settings/TrustedCaCard";

// Admin-only, like every other Admin-group page. This file is the layout
// shell and nothing else: each setting lives in its own card component
// under pages/settings/, next to the state it owns. It used to be all of
// them in one 1149-line component with 67 useState calls, where finding
// the four lines belonging to one setting meant reading past the other
// ten.
//
// Grouped rather than listed, because the flat order had drifted into
// nonsense: host retention, scan-log retention and storage all answer
// "how long do we keep things and what does that cost", but two unrelated
// scan thresholds sat between them.
//
// The cards sit in a responsive grid rather than a single column. That is
// the actual fix for the page's height: a settings form is capped at a
// readable width, so on a 1600px page one column left two thirds of the
// screen empty and made the page nearly three times taller than it needed
// to be.
export default function Settings({ me, onLogout }: { me: Me; onLogout: () => void }) {
  // The one piece of state that genuinely is shared: every card that
  // writes a setting gets the whole updated object back from PATCH
  // /api/settings/app, and handing it down keeps them all consistent
  // rather than each holding its own drifting copy.
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    api
      .appSettings()
      .then(setSettings)
      .catch(() => setLoadError(true));
  }, []);

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Settings</h2>

      {loadError && <p className="error">Could not load settings.</p>}

      <section>
        <h3 className="settings-group-title">Security</h3>
        <div className="settings-grid">
          <TlsCertificateCard me={me} />
          {settings && <RequireTotpCard settings={settings} onUpdated={setSettings} />}
          <TrustedCaCard me={me} />
        </div>
      </section>

      <section>
        <h3 className="settings-group-title">Scanning</h3>
        <div className="settings-grid">
          {settings && <ScanningCard settings={settings} onUpdated={setSettings} />}
        </div>
      </section>

      <section>
        <h3 className="settings-group-title">Data &amp; Retention</h3>
        <div className="settings-grid">
          {settings && <RetentionCard settings={settings} onUpdated={setSettings} />}
          {settings && <ScanLogRetentionCard settings={settings} onUpdated={setSettings} />}
          <StorageCard />
        </div>
      </section>

      <section>
        <h3 className="settings-group-title">Alerting</h3>
        <div className="settings-grid">
          {/* Six and seven fields respectively: too many for a 340px
              column, so both span two and lay their fields out in their
              own inner grid (.settings-grid-wide). */}
          <div className="settings-grid-wide">{settings && <AlertingCard settings={settings} onUpdated={setSettings} />}</div>
          <div className="settings-grid-wide">{settings && <SmtpCard settings={settings} onUpdated={setSettings} />}</div>
        </div>
      </section>

      <section>
        <h3 className="settings-group-title">Integrations</h3>
        <div className="settings-grid">
          <div className="settings-grid-wide">{settings && <HecCard me={me} settings={settings} onUpdated={setSettings} />}</div>
        </div>
      </section>
    </div>
  );
}
