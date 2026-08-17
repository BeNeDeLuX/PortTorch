import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router";
import { AdhocScanResult, api, Me, NSEProfileSelection, NucleiProfileSelection, ScannerAgent } from "../api";
import { IconPlay } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScanProfilePicker from "../components/ScanProfilePicker";
import NucleiProfilePicker from "../components/NucleiProfilePicker";
import { formatDateTime } from "../lib/formatDate";

// A one-shot "scan this right now" page - Schedule Scans minus all the
// interval/cron/run-at machinery, since an ad-hoc scan has no schedule at
// all: submitting fires a single scan_requests row that the chosen
// scanner picks up on its very next poll. Not admin-gated (requireOperator
// on the API side too), same access tier as the Rescan button.
export default function AdhocScans({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [loading, setLoading] = useState(true);

  const [scannerAgentId, setScannerAgentId] = useState("");
  const [targetSpec, setTargetSpec] = useState("");
  const [portSpec, setPortSpec] = useState("");
  const [profile, setProfile] = useState<NSEProfileSelection>({ kind: "default" });
  const [nucleiProfile, setNucleiProfile] = useState<NucleiProfileSelection>({ kind: "off" });

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<AdhocScanResult | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const agentList = await api.agents();
      const activeAgents = agentList.filter((a) => !a.revoked_at);
      setAgents(activeAgents);
      if (activeAgents.length > 0 && !scannerAgentId) {
        setScannerAgentId(activeAgents[0].id);
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!scannerAgentId || !targetSpec.trim() || !portSpec.trim()) return;

    setSubmitting(true);
    setError(null);
    setLastResult(null);
    try {
      const result = await api.createAdhocScan({
        scannerAgentId,
        targetSpec: targetSpec.trim(),
        portSpec: portSpec.trim(),
        profile,
        nucleiProfile,
      });
      setLastResult(result);
      setTargetSpec("");
      setPortSpec("");
      setProfile({ kind: "default" });
      setNucleiProfile({ kind: "off" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to queue scan");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Ad-hoc Scans</h2>
      <p className="empty">
        Fire a single scan right now - no schedule, no recurrence. Picked up by the chosen scanner on its very next
        poll.
      </p>

      {agents.length === 0 && !loading ? (
        <p className="empty">
          <Link to="/agents">Create a scanner agent</Link> first before an ad-hoc scan can be queued.
        </p>
      ) : (
        <form className="schedule-form" onSubmit={handleSubmit}>
          <label>
            Scanner
            <select value={scannerAgentId} onChange={(e) => setScannerAgentId(e.target.value)}>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Target
            <input
              placeholder="192.168.1.0/24, 2001:db8::1, or a DNS hostname"
              value={targetSpec}
              onChange={(e) => setTargetSpec(e.target.value)}
            />
          </label>
          <p className="empty">
            A DNS hostname is resolved by the scanner itself and used as the scan target - it's also automatically
            used as the TLS SNI / screenshot hostname, the same effect as setting a host's "probe hostname" by hand.
          </p>
          <label>
            Ports
            <input placeholder="1-1000" value={portSpec} onChange={(e) => setPortSpec(e.target.value)} />
          </label>
          <label>
            Scan profile
            <ScanProfilePicker value={profile} onChange={setProfile} />
          </label>
          <label>
            Nuclei profile
            <NucleiProfilePicker value={nucleiProfile} onChange={setNucleiProfile} />
          </label>

          <button type="submit" className="btn-icon-label" disabled={submitting}>
            <IconPlay /> {submitting ? "Queuing..." : "Start scan"}
          </button>
        </form>
      )}

      {error && <p className="callout-danger">{error}</p>}

      {lastResult && (
        <p className="callout-success">
          Scan queued for {lastResult.scannerAgentName} at {formatDateTime(lastResult.created_at, me.preferences)}.
          Profile: {lastResult.nse_profile_label ?? "Default"}
          {lastResult.nuclei_profile_label ? `, Nuclei: ${lastResult.nuclei_profile_label}` : ""}.
        </p>
      )}
    </div>
  );
}
