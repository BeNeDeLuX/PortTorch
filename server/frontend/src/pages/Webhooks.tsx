import { FormEvent, useEffect, useState } from "react";
import { api, Me, Webhook, WebhookChannelType, WebhookEvent } from "../api";
import { IconInfo, IconPause, IconPlay, IconPlus, IconSend, IconTrash } from "../components/icons";
import PageHeader from "../components/PageHeader";
import WebhookDeliveriesModal from "../components/WebhookDeliveriesModal";

const CHANNEL_LABELS: Record<WebhookChannelType, string> = {
  webhook: "Webhook",
  teams: "Microsoft Teams",
  email: "Email",
};

const ALL_EVENTS: Array<{ key: WebhookEvent; label: string }> = [
  { key: "host.new", label: "New host discovered" },
  { key: "port.opened", label: "Port newly open" },
  { key: "certificate.expiring_soon", label: "Certificate expiring soon" },
  { key: "webserver_certificate.expiring_soon", label: "Webserver's own TLS certificate expiring soon" },
  { key: "saved_search.match", label: "Saved search matched a new host" },
  { key: "vulnerability.high_epss", label: "High EPSS score on a known CVE" },
  { key: "vulnerability.kev", label: "CVE added to CISA's Known Exploited Vulnerabilities catalog" },
  { key: "digest.daily", label: "Daily digest (fleet-wide, once a day)" },
  { key: "scan.stale", label: "A running scan looks stalled" },
  { key: "scanner.update_failed", label: "Scanner self-update failed" },
  { key: "scan_queue.backlog", label: "A scanner's request queue is backing up" },
];

export default function Webhooks({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const isAdmin = me.role === "admin";
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [name, setName] = useState("");
  const [channelType, setChannelType] = useState<WebhookChannelType>("webhook");
  const [url, setUrl] = useState("");
  const [emailTo, setEmailTo] = useState("");
  const [events, setEvents] = useState<WebhookEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [historyWebhook, setHistoryWebhook] = useState<Webhook | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setWebhooks(await api.webhooks());
    } finally {
      setLoading(false);
    }
  }

  function toggleEventChoice(key: WebhookEvent) {
    setEvents((prev) => (prev.includes(key) ? prev.filter((e) => e !== key) : [...prev, key]));
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || events.length === 0) return;
    if (channelType !== "email" && !url.trim()) return;
    if (channelType === "email" && !emailTo.trim()) return;
    setError(null);
    try {
      await api.createWebhook({
        name: name.trim(),
        channelType,
        url: channelType === "email" ? undefined : url.trim(),
        emailTo: channelType === "email" ? emailTo.trim() : undefined,
        events,
      });
      setName("");
      setUrl("");
      setEmailTo("");
      setEvents([]);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create webhook");
    }
  }

  async function handleToggle(w: Webhook) {
    await api.setWebhookEnabled(w.id, !w.enabled);
    await load();
  }

  async function handleDelete(w: Webhook) {
    if (!window.confirm(`Delete webhook "${w.name}"?`)) return;
    await api.deleteWebhook(w.id);
    await load();
  }

  async function handleTest(w: Webhook) {
    const result = await api.testWebhook(w.id);
    setTestResult((prev) => ({ ...prev, [w.id]: result.ok ? "sent successfully" : `failed: ${result.error ?? result.status}` }));
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Webhooks</h2>
      <p className="host-meta">
        Sends a JSON POST (compatible with Slack/Discord incoming webhooks), a Microsoft Teams Adaptive Card, or an
        email, when a subscribed event occurs.
      </p>

      {error && <p className="error">{error}</p>}

      {isAdmin && (
        <form className="schedule-form" onSubmit={handleCreate}>
          <label>
            Name
            <input placeholder="e.g. security-team-slack" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label>
            Channel type
            <select value={channelType} onChange={(e) => setChannelType(e.target.value as WebhookChannelType)}>
              <option value="webhook">Webhook (Slack/Discord-compatible)</option>
              <option value="teams">Microsoft Teams</option>
              <option value="email">Email</option>
            </select>
          </label>
          {channelType === "email" ? (
            <label>
              Email address(es)
              <input
                placeholder="alerts@example.com, security@example.com"
                value={emailTo}
                onChange={(e) => setEmailTo(e.target.value)}
              />
            </label>
          ) : (
            <label>
              URL
              <input
                placeholder={channelType === "teams" ? "https://.../workflows/..." : "https://hooks.slack.com/..."}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </label>
          )}
          <div className="form-fullwidth-section">
            Events:
            <div className="checkbox-list">
              {ALL_EVENTS.map((e) => (
                <label key={e.key}>
                  <input type="checkbox" checked={events.includes(e.key)} onChange={() => toggleEventChoice(e.key)} />
                  {e.label}
                </label>
              ))}
            </div>
          </div>
          <button type="submit" className="btn-icon-label">
            <IconPlus /> Create
          </button>
        </form>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : webhooks.length === 0 ? (
        <p className="empty">No webhooks configured yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Channel</th>
              <th>Target</th>
              <th>Events</th>
              <th>Status</th>
              <th></th>
              {isAdmin && <th></th>}
            </tr>
          </thead>
          <tbody>
            {webhooks.map((w) => (
              <tr key={w.id}>
                <td>{w.name}</td>
                <td>{CHANNEL_LABELS[w.channel_type]}</td>
                <td className="banner">{w.channel_type === "email" ? w.email_to : w.url}</td>
                <td>{w.events.join(", ")}</td>
                <td>{w.enabled ? "active" : "paused"}</td>
                <td>
                  <button className="btn-icon-label" onClick={() => setHistoryWebhook(w)}>
                    <IconInfo /> History
                  </button>
                </td>
                {isAdmin && (
                  <td>
                    <button className="btn-icon-label" onClick={() => handleToggle(w)}>
                      {w.enabled ? (
                        <>
                          <IconPause /> Pause
                        </>
                      ) : (
                        <>
                          <IconPlay /> Activate
                        </>
                      )}
                    </button>{" "}
                    <button className="btn-icon-label" onClick={() => handleTest(w)}>
                      <IconSend /> Test
                    </button>{" "}
                    <button className="btn-icon-label" onClick={() => handleDelete(w)}>
                      <IconTrash /> Delete
                    </button>
                    {testResult[w.id] && <div className="host-meta">{testResult[w.id]}</div>}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {historyWebhook && (
        <WebhookDeliveriesModal
          webhookId={historyWebhook.id}
          webhookName={historyWebhook.name}
          preferences={me.preferences}
          onClose={() => setHistoryWebhook(null)}
        />
      )}
    </div>
  );
}
