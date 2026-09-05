import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings, HecStatus, Me } from "../../api";
import { IconRefresh, IconSave, IconSend } from "../../components/icons";
import { formatDateTime } from "../../lib/formatDate";
import SettingsCard from "./SettingsCard";

export default function HecCard({
  me,
  settings,
  onUpdated,
}: {
  me: Me;
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [url, setUrl] = useState(settings.hec.url ?? "");
  // Blank means "keep the stored token" - the API never returns it, so
  // the form cannot prefill it. tokenSet is what distinguishes that from
  // "no token at all".
  const [token, setToken] = useState("");
  const [audit, setAudit] = useState(settings.hec.auditEnabled);
  const [scanLog, setScanLog] = useState(settings.hec.scanLogEnabled);
  const [index, setIndex] = useState(settings.hec.index ?? "");
  const [sourcetype, setSourcetype] = useState(settings.hec.sourcetype ?? "");
  const [verifyTls, setVerifyTls] = useState(settings.hec.verifyTls);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [status, setStatus] = useState<HecStatus | null>(null);

  useEffect(() => {
    setUrl(settings.hec.url ?? "");
    setAudit(settings.hec.auditEnabled);
    setScanLog(settings.hec.scanLogEnabled);
    setIndex(settings.hec.index ?? "");
    setSourcetype(settings.hec.sourcetype ?? "");
    setVerifyTls(settings.hec.verifyTls);
  }, [settings.hec]);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      onUpdated(
        await api.updateAppSettings({
          hec: {
            url: url.trim() || null,
            auditEnabled: audit,
            scanLogEnabled: scanLog,
            index: index.trim() || null,
            sourcetype: sourcetype.trim() || null,
            verifyTls,
            // Blank leaves the stored token alone; the field is only sent
            // when something was actually typed into it.
            ...(token.trim() ? { token: token.trim() } : {}),
          },
        })
      );
      setToken("");
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save these settings.");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTestResult(null);
    try {
      const result = await api.testHec();
      setTestResult(result.ok ? "Test event accepted by the collector." : `Failed: ${result.error}`);
    } catch (err) {
      setTestResult(err instanceof Error ? err.message : "Test failed.");
    }
  }

  async function handleForwardNow() {
    setTestResult(null);
    try {
      const counts = await api.forwardHecNow();
      setTestResult(`Forwarded ${counts.audit} audit event(s) and ${counts.scanLog} scan log event(s).`);
      await loadStatus();
    } catch (err) {
      setTestResult(err instanceof Error ? err.message : "Forwarding failed.");
    }
  }

  async function loadStatus() {
    try {
      setStatus(await api.hecStatus());
    } catch {
      setStatus(null);
    }
  }

  return (
    <SettingsCard
      title="SIEM Forwarding (HTTP Event Collector)"
      description={
        <>
          Ships the audit trail and the scanners' own scan logs to a SIEM over an HTTP Event Collector - Splunk's HEC
          and collectors that speak its shape. Each stream is forwarded from a stored cursor rather than
          fire-and-forget, so a collector that is unreachable for a while causes the next run to catch up instead of
          leaving a silent gap. Delivery is at-least-once: a repeat is possible after a connection breaks mid-batch, a
          missing event is not. Retention still applies - if the collector stays unreachable longer than the retention
          window, those rows are deleted before they were ever forwarded.
        </>
      }
      error={error}
      notice={saved && <p className="callout-success">SIEM forwarding settings saved.</p>}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label className="settings-field-wide">
          Collector URL
          <input placeholder="https://splunk.internal:8088" value={url} onChange={(e) => setUrl(e.target.value)} />
          <span className="empty">
            The base URL. /services/collector/event is appended automatically if it isn't already there.
          </span>
        </label>
        <label>
          Token
          <input
            type="password"
            placeholder={settings.hec.tokenSet ? "unchanged" : "HEC token"}
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <span className="empty">
            {settings.hec.tokenSet
              ? "A token is stored. Leave blank to keep it."
              : "No token stored yet - forwarding stays off until one is set."}
          </span>
        </label>
        <label>
          Index (optional)
          <input placeholder="e.g. netsec" value={index} onChange={(e) => setIndex(e.target.value)} />
        </label>
        <label>
          Sourcetype (optional)
          <input
            placeholder="default: porttorch:audit / porttorch:scan"
            value={sourcetype}
            onChange={(e) => setSourcetype(e.target.value)}
          />
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={audit} onChange={(e) => setAudit(e.target.checked)} />
          Forward the audit log (who did what in this dashboard)
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={scanLog} onChange={(e) => setScanLog(e.target.checked)} />
          Forward scan logs (each scanner's own per-job log lines)
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)} />
          Verify the collector's TLS certificate (turn off only for a self-signed internal collector)
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={saving}>
            <IconSave /> {saving ? "Saving..." : "Save forwarding settings"}
          </button>
          <button type="button" className="btn-icon-label" onClick={handleTest}>
            <IconSend /> Send a test event
          </button>
          <button type="button" className="btn-icon-label" onClick={handleForwardNow}>
            <IconRefresh /> Forward pending now
          </button>
          <button type="button" className="btn-icon-label" onClick={loadStatus}>
            <IconRefresh /> Check status
          </button>
        </div>
      </form>

      {testResult && <p className="settings-state">{testResult}</p>}
      {status && (
        <p className="settings-state">
          {status.eventsForwarded} event(s) forwarded in total ·{" "}
          {status.lastSuccessAt
            ? `last success ${formatDateTime(status.lastSuccessAt, me.preferences)}`
            : "nothing forwarded yet"}
          {status.lastError && ` · last error: ${status.lastError}`}
        </p>
      )}
    </SettingsCard>
  );
}
