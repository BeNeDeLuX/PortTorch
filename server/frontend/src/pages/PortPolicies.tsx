import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router";
import { api, Me, PortPolicy, PortPolicySummary, PortPolicyViolation, ScannerAgent } from "../api";
import { IconEdit, IconPlus, IconSave, IconSearch, IconTrash, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

const ALL_SCANNERS = "";

interface FormState {
  name: string;
  network: string;
  scannerAgentId: string;
  mode: "allow" | "deny";
  ports: string;
  note: string;
}

const EMPTY: FormState = { name: "", network: "", scannerAgentId: ALL_SCANNERS, mode: "allow", ports: "", note: "" };

function ruleText(p: Pick<PortPolicy, "mode" | "ports">): string {
  return p.mode === "allow" ? `only ${p.ports}` : `never ${p.ports}`;
}

// What may be open where. A baseline records what a network looked like; a
// policy states what it is allowed to look like, and every open port that
// breaks it is listed here and reported once through port_policy.violation.
export default function PortPolicies({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const isAdmin = me.role === "admin";
  const [policies, setPolicies] = useState<PortPolicySummary[]>([]);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ policy: PortPolicy; items: PortPolicyViolation[]; truncated: boolean } | null>(null);

  async function load() {
    setLoading(true);
    try {
      setPolicies(await api.portPolicies());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load port policies");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    api.agents().then((a) => setAgents(a.filter((x) => !x.revoked_at)));
  }, []);

  function startEdit(p: PortPolicySummary) {
    setEditingId(p.id);
    setForm({
      name: p.name,
      network: p.network,
      scannerAgentId: p.scanner_agent_id ?? ALL_SCANNERS,
      mode: p.mode,
      ports: p.ports,
      note: p.note ?? "",
    });
    window.scrollTo({ top: 0 });
  }

  function resetForm() {
    setEditingId(null);
    setForm(EMPTY);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const input = {
      name: form.name.trim(),
      network: form.network.trim(),
      scannerAgentId: form.scannerAgentId || null,
      mode: form.mode,
      ports: form.ports.trim(),
      note: form.note.trim() || null,
    };
    try {
      if (editingId) await api.updatePortPolicy(editingId, input);
      else await api.createPortPolicy(input);
      resetForm();
      setDetail(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the policy");
    }
  }

  async function openDetail(p: PortPolicySummary) {
    setError(null);
    try {
      const r = await api.portPolicy(p.id);
      setDetail({ policy: r.policy, items: r.violations.items, truncated: r.violations.truncated });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the violations");
    }
  }

  async function toggleEnabled(p: PortPolicySummary) {
    await api.updatePortPolicy(p.id, { enabled: !p.enabled });
    await load();
  }

  async function handleDelete(p: PortPolicySummary) {
    if (!window.confirm(`Delete the policy "${p.name}"? Its violations will no longer be listed or reported.`)) return;
    await api.deletePortPolicy(p.id);
    if (detail?.policy.id === p.id) setDetail(null);
    await load();
  }

  const active = policies.filter((p) => p.enabled);
  const violating = active.filter((p) => p.violations > 0);
  const totalViolations = active.reduce((n, p) => n + p.violations, 0);

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Port Policies</h2>
      <p className="host-meta">
        Which ports a network may have open. <strong>Allow</strong> means only the listed ports may be open, so every other
        open port is a violation. <strong>Deny</strong> means the listed ports must never be open. Ports use the scan
        grammar: <code>22,80,443</code>, ranges like <code>8000-8100</code>, and <code>U:53</code> for UDP. A bare number
        means TCP. Violations come from each port's latest scan result, so a port a scan recorded closed stops violating.
        A port that silently stopped answering keeps its last open record until a scan says otherwise, as everywhere else.
        Each new violation is reported once through the <code>port_policy.violation</code> alert.
      </p>

      {error && <p className="callout-danger">{error}</p>}

      {isAdmin && (
        <form className="schedule-form" onSubmit={handleSubmit}>
          <label>
            Name
            <input placeholder="DMZ web servers" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </label>
          <label>
            Network
            <input placeholder="10.46.0.0/16 or 10.46" value={form.network} onChange={(e) => setForm({ ...form, network: e.target.value })} />
          </label>
          <label>
            Scope
            <select value={form.scannerAgentId} onChange={(e) => setForm({ ...form, scannerAgentId: e.target.value })}>
              <option value={ALL_SCANNERS}>All scanners</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Rule
            <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value as "allow" | "deny" })}>
              <option value="allow">Only these ports may be open</option>
              <option value="deny">These ports must never be open</option>
            </select>
          </label>
          <label>
            Ports
            <input placeholder="22,80,443" value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} />
          </label>
          <label>
            Note
            <input placeholder="optional" value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
          </label>
          <button type="submit" className="btn-icon-label" disabled={!form.name.trim() || !form.network.trim() || !form.ports.trim()}>
            {editingId ? (
              <>
                <IconSave /> Save changes
              </>
            ) : (
              <>
                <IconPlus /> Add policy
              </>
            )}
          </button>
          {editingId && (
            <button type="button" className="link-button btn-icon-label" onClick={resetForm}>
              <IconX /> Cancel
            </button>
          )}
        </form>
      )}

      {policies.length > 0 && (
        <div className="summary-cards">
          <div className="summary-card">
            <span className="summary-card-value">{active.length}</span>
            <span className="summary-card-label">active policies</span>
          </div>
          <div className={`summary-card${violating.length > 0 ? " summary-card-warn" : ""}`}>
            <span className="summary-card-value">{violating.length}</span>
            <span className="summary-card-label">violated</span>
          </div>
          <div className={`summary-card${totalViolations > 0 ? " summary-card-warn" : ""}`}>
            <span className="summary-card-value">{totalViolations}</span>
            <span className="summary-card-label">open ports in violation</span>
          </div>
        </div>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : policies.length === 0 ? (
        <p className="empty">No port policies yet.</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Policy</th>
                <th>Network</th>
                <th>Rule</th>
                <th>Scope</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className={p.enabled ? undefined : "row-muted"}>
                  <td>
                    <strong>{p.name}</strong>
                    {p.note && <div className="host-meta">{p.note}</div>}
                  </td>
                  <td>{p.network}</td>
                  <td>
                    <code>{ruleText(p)}</code>
                  </td>
                  <td>{p.scanner_agent_name ?? "All scanners"}</td>
                  <td>
                    {!p.enabled ? (
                      <span className="host-meta">disabled</span>
                    ) : p.violations === 0 ? (
                      <span className="baseline-ok">compliant</span>
                    ) : (
                      <span className="stale-badge">
                        {p.violations}
                        {p.truncated ? "+" : ""} port{p.violations === 1 ? "" : "s"} on {p.violatingHosts} host
                        {p.violatingHosts === 1 ? "" : "s"}
                      </span>
                    )}
                  </td>
                  <td>
                    <div className="inline-actions">
                      <button className="btn-icon-label" onClick={() => openDetail(p)}>
                        <IconSearch /> Details
                      </button>
                      {isAdmin && (
                        <>
                          <button className="btn-icon-label" onClick={() => startEdit(p)}>
                            <IconEdit /> Edit
                          </button>
                          <button className="btn-icon-label" onClick={() => toggleEnabled(p)}>
                            {p.enabled ? "Disable" : "Enable"}
                          </button>
                          <button className="btn-icon-label" onClick={() => handleDelete(p)}>
                            <IconTrash /> Delete
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail && (
        <section className="baseline-detail">
          <h3>
            {detail.policy.name}
            <span className="host-meta">
              {" "}
              · {detail.policy.network} · {ruleText(detail.policy)}
            </span>
          </h3>
          <div className="inline-actions">
            <button className="btn-icon-label" onClick={() => setDetail(null)}>
              <IconX /> Close
            </button>
          </div>
          {detail.truncated && <p className="callout-warning">Showing the first {detail.items.length}. Narrow the network to see the rest.</p>}
          {detail.items.length === 0 ? (
            <p className="empty">No open port violates this policy.</p>
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Scanner</th>
                    <th>Last seen open</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.items.map((v) => (
                    <tr key={`${v.hostId}-${v.port}-${v.protocol}`}>
                      <td>
                        <Link className="port-link" to={`/hosts/${v.hostId}`}>
                          {v.ip}
                        </Link>
                        {v.hostname && <span className="host-meta"> {v.hostname}</span>}
                      </td>
                      <td>
                        {v.port}/{v.protocol}
                      </td>
                      <td>{[v.serviceName, v.serviceProduct].filter(Boolean).join(" · ") || "-"}</td>
                      <td className="host-meta">{v.scannerAgentName ?? "?"}</td>
                      <td className="host-meta">{formatDateTime(v.observedAt, me.preferences)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
