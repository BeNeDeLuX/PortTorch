import { FormEvent, useEffect, useState } from "react";
import { AppSettings, api } from "../../api";
import { IconRocket, IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "../../components/SettingsCard";

export default function ProxyCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [httpUrl, setHttpUrl] = useState(settings.proxy.httpUrl ?? "");
  const [httpsUrl, setHttpsUrl] = useState(settings.proxy.httpsUrl ?? "");
  const [noProxy, setNoProxy] = useState(settings.proxy.noProxy ?? "");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testOk, setTestOk] = useState<boolean | null>(null);

  useEffect(() => {
    setHttpUrl(settings.proxy.httpUrl ?? "");
    setHttpsUrl(settings.proxy.httpsUrl ?? "");
    setNoProxy(settings.proxy.noProxy ?? "");
  }, [settings.proxy.httpUrl, settings.proxy.httpsUrl, settings.proxy.noProxy]);

  const dirty =
    httpUrl !== (settings.proxy.httpUrl ?? "") ||
    httpsUrl !== (settings.proxy.httpsUrl ?? "") ||
    noProxy !== (settings.proxy.noProxy ?? "");

  const anyConfigured = Boolean(settings.proxy.httpUrl || settings.proxy.httpsUrl);

  async function save(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const updated = await api.updateAppSettings({
        proxy: { httpUrl: httpUrl.trim() || null, httpsUrl: httpsUrl.trim() || null, noProxy: noProxy.trim() || null },
      });
      onUpdated(updated);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save.");
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    setTesting(true);
    setTestResult(null);
    setTestOk(null);
    try {
      const result = await api.testProxy();
      setTestOk(result.ok);
      setTestResult(
        result.ok
          ? `Reached the CVE feed in ${result.durationMs} ms, ${
              result.viaProxy ? `through ${result.viaProxy}` : "directly, without a proxy"
            }.`
          : `Failed${result.viaProxy ? ` through ${result.viaProxy}` : " (direct, no proxy in use)"}: ${
              result.error ?? `status ${result.status}`
            }`
      );
    } catch (err) {
      setTestOk(false);
      setTestResult(err instanceof Error ? err.message : "The test could not be run.");
    } finally {
      setTesting(false);
    }
  }

  return (
    <SettingsCard
      title="Outbound Proxy"
      description={
        <>
          Every call PortTorch makes out to the internet goes through this: the CVE, EPSS and KEV feeds, the scanner
          release check, the Docker Hub version check, and delivery to alert channels and a SIEM collector. Leave it
          empty to use <code>HTTP_PROXY</code>/<code>HTTPS_PROXY</code>/<code>NO_PROXY</code> from the environment
          instead - a value here takes over from those.
        </>
      }
      error={error}
    >
      <form className="settings-form" onSubmit={save}>
        <label className="settings-field-wide">
          Proxy for https targets
          <input
            value={httpsUrl}
            onChange={(e) => setHttpsUrl(e.target.value)}
            placeholder="http://proxy.internal:3128"
            disabled={saving}
          />
        </label>
        <label className="settings-field-wide">
          Proxy for http targets
          <input
            value={httpUrl}
            onChange={(e) => setHttpUrl(e.target.value)}
            placeholder="http://proxy.internal:3128"
            disabled={saving}
          />
        </label>
        <label className="settings-field-wide">
          Reached without the proxy (comma-separated)
          <input
            value={noProxy}
            onChange={(e) => setNoProxy(e.target.value)}
            placeholder="localhost,127.0.0.1,.internal"
            disabled={saving}
          />
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={saving || !dirty}>
            <IconSave /> {saving ? "Saving..." : "Save"}
          </button>
          <button type="button" className="btn-icon-label" onClick={test} disabled={testing || dirty}>
            <IconRocket /> {testing ? "Testing..." : "Test connection"}
          </button>
          <SaveState saved={saved} dirty={dirty} />
        </div>
      </form>
      {testResult && <p className={testOk ? "callout-success" : "error"}>{testResult}</p>}
      <p className="host-meta">
        The test fetches the real CVE feed over the same transport the syncs use, and says whether it went through a
        proxy - a direct success on a network that only allows proxied egress means the setting is being ignored,
        which would otherwise read as a pass.
        {!anyConfigured && " Nothing is configured here, so the test uses whatever the environment provides."}
      </p>
      <p className="host-meta">
        Credentials belong in the URL (<code>http://user:pass@proxy:3128</code>). They are stored as given and never
        logged - only the proxy's host appears in the audit trail. A proxy that terminates TLS with its own
        certificate needs that CA uploaded under Trusted CA Certificates; every outbound call honours it.
      </p>
    </SettingsCard>
  );
}
