import { FormEvent, useEffect, useState } from "react";
import { api, Me, ScannerAgent, Webhook, WebhookChannelType, WebhookEvent } from "../api";
import { IconInfo, IconPause, IconPlay, IconPlus, IconSend, IconTrash } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import WebhookDeliveriesModal from "../components/WebhookDeliveriesModal";

const CHANNEL_LABELS: Record<WebhookChannelType, string> = {
  webhook: "Webhook",
  teams: "Microsoft Teams",
  email: "Email",
};

// Labels only - the *list* comes from the server (GET /api/webhooks/events)
// so it cannot drift again. An event with no label here still appears,
// under its own name: a missing label is cosmetic, a missing event is a
// channel nobody can subscribe to, which is exactly what happened when
// this array was the list.
const EVENT_LABELS: Record<string, string> = {
  "host.new": "New host discovered",
  "port.opened": "Port newly open",
  "port.closed": "Port no longer open",
  "certificate.expiring_soon": "Certificate expiring soon",
  "webserver_certificate.expiring_soon": "Webserver's own TLS certificate expiring soon",
  "saved_search.match": "Saved search matched a new host",
  "vulnerability.high_epss": "High EPSS score on a known CVE",
  "vulnerability.kev": "CVE added to CISA's Known Exploited Vulnerabilities catalog",
  "digest.daily": "Daily digest (fleet-wide, once a day)",
  "scan.stale": "A running scan looks stalled",
  "scanner.update_failed": "Scanner self-update failed",
  "scan_queue.backlog": "A scanner's request queue is backing up",
  "nuclei.finding": "Nuclei web vulnerability finding",
  "scanner.offline": "Scanner stopped reporting in",
  "host.disappeared": "Host stopped responding",
  "network.coverage_stale": "Tracked network has not been scanned",
  "ssh_key.shared": "SSH host key shared by several addresses",
  "ca_certificate.expiring_soon": "A trusted CA certificate is expiring",
};
export default function Webhooks({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const isAdmin = me.role === "admin";
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [name, setName] = useState("");
  const [channelType, setChannelType] = useState<WebhookChannelType>("webhook");
  const [url, setUrl] = useState("");
  const [emailTo, setEmailTo] = useState("");
  const [events, setEvents] = useState<WebhookEvent[]>([]);
  const [filterScannerAgentIds, setFilterScannerAgentIds] = useState<string[]>([]);
  const [filterTags, setFilterTags] = useState("");
  const [minSeverity, setMinSeverity] = useState("");
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [allEvents, setAllEvents] = useState<WebhookEvent[]>([]);
  const [verifyTls, setVerifyTls] = useState(true);
  // Non-null puts the form into edit mode for that channel - deliberately
  // the same form rather than a second one, so the two can't drift on
  // which fields exist or how they validate.
  const [editing, setEditing] = useState<Webhook | null>(null);
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
      const [hookList, agentList, eventList] = await Promise.all([
        api.webhooks(),
        api.agents(),
        api.webhookEvents(),
      ]);
      setWebhooks(hookList);
      setAgents(agentList.filter((a) => !a.revoked_at));
      setAllEvents(eventList);
    } finally {
      setLoading(false);
    }
  }

  function toggleEventChoice(key: WebhookEvent) {
    setEvents((prev) => (prev.includes(key) ? prev.filter((e) => e !== key) : [...prev, key]));
  }

  function startEditing(w: Webhook) {
    setEditing(w);
    setName(w.name);
    setChannelType(w.channel_type);
    setUrl(w.url ?? "");
    setEmailTo(w.email_to ?? "");
    setEvents(w.events);
    setFilterScannerAgentIds(w.filter_scanner_agent_ids);
    setFilterTags(w.filter_tags.join(", "));
    setMinSeverity(w.min_severity ?? "");
    setVerifyTls(w.verify_tls);
    setError(null);
  }

  function resetForm() {
    setEditing(null);
    setName("");
    setUrl("");
    setEmailTo("");
    setEvents([]);
    setFilterScannerAgentIds([]);
    setFilterTags("");
    setMinSeverity("");
    setVerifyTls(true);
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || events.length === 0) return;
    if (channelType !== "email" && !url.trim()) return;
    if (channelType === "email" && !emailTo.trim()) return;
    setError(null);

    const tags = filterTags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    if (editing) {
      try {
        await api.updateWebhook(editing.id, {
          name: name.trim(),
          ...(channelType === "email" ? { emailTo: emailTo.trim() } : { url: url.trim() }),
          events,
          filterScannerAgentIds,
          filterTags: tags,
          // Explicitly null rather than omitted, so clearing the dropdown
          // actually removes the floor instead of silently keeping it.
          minSeverity: minSeverity || null,
          verifyTls,
        });
        resetForm();
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to update webhook");
      }
      return;
    }

    try {
      await api.createWebhook({
        name: name.trim(),
        channelType,
        url: channelType === "email" ? undefined : url.trim(),
        emailTo: channelType === "email" ? emailTo.trim() : undefined,
        events,
        filterScannerAgentIds,
        // Comma-separated in the field, an array on the wire - same
        // convention as every other multi-value input in this app.
        filterTags: tags,
        minSeverity: minSeverity || null,
        verifyTls,
      });
      resetForm();
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
              {allEvents.map((key) => (
                <label key={key}>
                  <input type="checkbox" checked={events.includes(key)} onChange={() => toggleEventChoice(key)} />
                  {EVENT_LABELS[key] ?? key}
                </label>
              ))}
            </div>
          </div>
          <div className="form-fullwidth-section">
            Only alert for (optional):
            <div className="inline-form">
              <label className="hide-empty-toggle">
                Scanners
                <ScannerMultiSelect agents={agents} selectedIds={filterScannerAgentIds} onChange={setFilterScannerAgentIds} />
              </label>
              <label className="hide-empty-toggle">
                Host tags
                <input
                  placeholder="e.g. prod, dmz"
                  value={filterTags}
                  onChange={(e) => setFilterTags(e.target.value)}
                />
              </label>
              <label className="hide-empty-toggle">
                Minimum severity
                <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
                  <option value="">any</option>
                  <option value="info">info</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
            </div>
            <label className="hide-empty-toggle">
              <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)} />
              Verify the target's TLS certificate. For an internal endpoint, uploading its CA under Settings is the
              better fix than turning this off.
            </label>
            <p className="host-meta">
              Empty means everything, which is how every channel behaved before these existed. Scanner and tag filters
              narrow the events that are <em>about a host</em> - they deliberately never suppress fleet-level alerts
              like "scanner stopped reporting in" or a queue backlog, so narrowing the noisy alerts cannot silently
              cost you the ones that matter most. The severity minimum applies to alerts that carry one, which today
              means nuclei findings.
            </p>
          </div>
          <div className="inline-form">
            <button type="submit" className="btn-icon-label">
              <IconPlus /> {editing ? "Save changes" : "Create"}
            </button>
            {editing && (
              <button type="button" className="btn-icon-label" onClick={resetForm}>
                Cancel
              </button>
            )}
          </div>
        </form>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : webhooks.length === 0 ? (
        <p className="empty">No webhooks configured yet.</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Channel</th>
                <th>Target</th>
                <th>Events</th>
                <th>Filters</th>
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
                  <td>
                    {(() => {
                      const parts: string[] = [];
                      if (w.filter_scanner_agent_ids.length > 0) {
                        parts.push(
                          `scanners: ${w.filter_scanner_agent_ids
                            .map((id) => agents.find((a) => a.id === id)?.name ?? id.slice(0, 8))
                            .join(", ")}`
                        );
                      }
                      if (w.filter_tags.length > 0) parts.push(`tags: ${w.filter_tags.join(", ")}`);
                      if (w.min_severity) parts.push(`min ${w.min_severity}`);
                      if (!w.verify_tls) parts.push("TLS unverified");
                      return parts.length > 0 ? parts.join(" · ") : "none";
                    })()}
                  </td>
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
                      <button className="btn-icon-label" onClick={() => startEditing(w)}>
                        <IconPlus /> Edit
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
        </div>
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
