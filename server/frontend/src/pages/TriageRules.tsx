import { FormEvent, useEffect, useState } from "react";
import { api, FindingTriageRule, Me, TRIAGE_LABEL, TriageState } from "../api";
import { IconPlus, IconTrash } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

const STATES: TriageState[] = ["false_positive", "accepted_risk", "fixed"];

function identifierOf(rule: FindingTriageRule): string {
  return (rule.kind === "cve" ? rule.cve_id : rule.template_id) ?? "-";
}

// Fleet-wide triage rules were reachable from the Vulnerabilities and Web
// Findings pages - but only as a second step after triaging a finding on
// one host, and once set there was nowhere in the dashboard to see a rule
// again, let alone remove it. The endpoints for both existed the whole
// time; only this page was missing, so a finding could be silenced
// fleet-wide and then not be found again to take it back.
export default function TriageRules({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [rules, setRules] = useState<FindingTriageRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [kind, setKind] = useState<"cve" | "nuclei">("nuclei");
  const [identifier, setIdentifier] = useState("");
  const [state, setState] = useState<TriageState>("false_positive");
  const [note, setNote] = useState("");
  const [query, setQuery] = useState("");

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setRules(await api.findingTriageRules());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load triage rules.");
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    const value = identifier.trim();
    if (!value) return;
    setBusy(true);
    setError(null);
    try {
      await api.createFindingTriageRule(
        kind === "cve" ? { kind: "cve", cveId: value } : { kind: "nuclei", templateId: value },
        state,
        note.trim() || undefined
      );
      setIdentifier("");
      setNote("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the rule.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(rule: FindingTriageRule) {
    if (
      !window.confirm(
        `Remove the fleet-wide rule for ${identifierOf(rule)}? The finding comes back everywhere it still applies, ` +
          `except on hosts where somebody triaged it individually.`
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteFindingTriageRule(rule.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove the rule.");
    } finally {
      setBusy(false);
    }
  }

  const trimmed = query.trim().toLowerCase();
  const visible = rules.filter(
    (r) =>
      !trimmed ||
      identifierOf(r).toLowerCase().includes(trimmed) ||
      (r.note ?? "").toLowerCase().includes(trimmed) ||
      (r.created_by ?? "").toLowerCase().includes(trimmed)
  );

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Fleet Triage Rules</h2>
      <p className="host-meta">
        A rule dismisses one finding across the <strong>whole fleet</strong> - every host that has it now, every host
        nobody has looked at, and every host discovered later. That is what makes it the right tool for a template
        that matches everywhere and tells you nothing, and the wrong tool for a decision about one machine.
      </p>
      <p className="host-meta">
        A decision made on an individual host still wins over a rule, because somebody looked at that host and
        decided. Rules carry no review date - only per-host decisions can expire. And the state matters:{" "}
        <strong>{TRIAGE_LABEL.false_positive}</strong> and <strong>{TRIAGE_LABEL.fixed}</strong> drop the finding out
        of the host list's risk indicator and the Scan Stats security charts, while{" "}
        <strong>{TRIAGE_LABEL.accepted_risk}</strong> deliberately still counts there - deciding to live with an
        exposure does not make the host less exposed. All three silence EPSS and KEV alerting.
      </p>

      {error && <p className="error">{error}</p>}

      <form className="tag-form rule-form" onSubmit={handleCreate}>
        <select value={kind} onChange={(e) => setKind(e.target.value as "cve" | "nuclei")} disabled={busy}>
          <option value="nuclei">Web finding (nuclei template)</option>
          <option value="cve">CVE</option>
        </select>
        <input
          className="rule-identifier"
          value={identifier}
          onChange={(e) => setIdentifier(e.target.value)}
          placeholder={kind === "cve" ? "CVE-2019-11248" : "http-missing-security-headers"}
          disabled={busy}
        />
        <select value={state} onChange={(e) => setState(e.target.value as TriageState)} disabled={busy}>
          {STATES.map((s) => (
            <option key={s} value={s}>
              {TRIAGE_LABEL[s]}
            </option>
          ))}
        </select>
        <input
          className="rule-note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Why (optional, but the next person will thank you)"
          disabled={busy}
        />
        <button type="submit" className="btn-icon-label" disabled={busy || !identifier.trim()}>
          <IconPlus /> Add rule
        </button>
      </form>

      {rules.length > 0 && (
        <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
          <input
            placeholder="Search by CVE, template, note, or who set it..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </form>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : rules.length === 0 ? (
        <p className="empty">
          No fleet-wide rules. Findings are triaged per host until one is set here, or from the "apply fleet-wide"
          button next to a triaged finding on the Vulnerabilities and Web Findings pages.
        </p>
      ) : visible.length === 0 ? (
        <p className="empty">No rules match the current search.</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Finding</th>
                <th>State</th>
                <th>Note</th>
                <th>Set by</th>
                <th>Set at</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {visible.map((rule) => (
                <tr key={rule.id}>
                  <td>{rule.kind === "cve" ? "CVE" : "Web finding"}</td>
                  <td>{identifierOf(rule)}</td>
                  <td>
                    <span className={`triage-badge triage-${rule.state}`}>{TRIAGE_LABEL[rule.state]}</span>
                  </td>
                  <td>{rule.note || <span className="host-meta">-</span>}</td>
                  <td>{rule.created_by ?? "-"}</td>
                  <td>{formatDateTime(rule.created_at, me.preferences)}</td>
                  <td>
                    <button
                      type="button"
                      className="link-button btn-icon-label"
                      disabled={busy}
                      onClick={() => handleDelete(rule)}
                    >
                      <IconTrash /> remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
