import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router";
import { api, Me, NmapImportResult, ScannerAgent } from "../api";
import PageHeader from "../components/PageHeader";
import { IconUpload } from "../components/icons";

export default function ImportScan({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [scannerAgentId, setScannerAgentId] = useState("");
  const [targetSpec, setTargetSpec] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<NmapImportResult | null>(null);

  useEffect(() => {
    api.agents().then((list) => {
      const active = list.filter((a) => !a.revoked_at);
      setAgents(active);
      if (active.length === 1) setScannerAgentId(active[0].id);
    });
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!file || !scannerAgentId) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.importNmapXml(file, scannerAgentId, targetSpec.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  }

  const canEdit = me.role === "admin" || me.role === "operator";

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Import Scan</h2>
      <p className="host-meta">
        Everything else here exists because a PortTorch scanner found it, which leaves no way in for an nmap run
        from a network with no agent, or a scan that predates this platform. Upload its <code>-oX</code> XML and
        the results land exactly as a scanner submission would: same hosts, same service detection, same auto-tags,
        same new-host and port-change alerts.
      </p>

      {!canEdit ? (
        <p className="empty">Importing scan results needs operator or admin rights.</p>
      ) : agents.length === 0 ? (
        <p className="empty">
          No active scanner agents. Results have to be attributed to one, so create an agent on the{" "}
          <Link to="/agents">Scanner Agents</Link> page first.
        </p>
      ) : (
        <form className="schedule-form" onSubmit={handleSubmit}>
          <label>
            nmap XML file
            <input
              type="file"
              accept=".xml,text/xml,application/xml"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>
          <label>
            Attribute to scanner
            <select value={scannerAgentId} onChange={(e) => setScannerAgentId(e.target.value)}>
              <option value="">Choose a scanner...</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Scanned range (optional)
            <input
              placeholder="10.0.0.0/24 - what nmap actually swept"
              value={targetSpec}
              onChange={(e) => setTargetSpec(e.target.value)}
            />
          </label>
          <button type="submit" className="btn-icon-label" disabled={busy || !file || !scannerAgentId}>
            <IconUpload /> {busy ? "Importing..." : "Import"}
          </button>
        </form>
      )}

      {canEdit && agents.length > 0 && (
        <p className="host-meta">
          A host's identity here is its address <em>plus</em> the scanner it belongs to, since private ranges repeat
          across unrelated networks - so the results have to be attributed to one. The scanned range matters for{" "}
          <Link to="/networks">Network Coverage</Link>: a /24 sweep that found three hosts covered 256 addresses,
          not three, and nothing in the file states that reliably. Left blank, only the addresses that answered are
          recorded as covered.
        </p>
      )}

      {error && <p className="error">{error}</p>}

      {result && (
        <div className="callout-success">
          <p>
            Imported {result.hostsImported} host(s) with {result.openPortsFound} open port(s)
            {result.hostsDown > 0 && ` (${result.hostsDown} host(s) were down and not imported)`}.
          </p>
          <p className="host-meta">
            Recorded as a completed scan of <code>{result.targetSpec}</code>
            {result.portSpec && (
              <>
                {" "}
                over ports <code>{result.portSpec}</code>
              </>
            )}
            . {result.nmapArgs && <>Original command: <code>{result.nmapArgs}</code>.</>}
          </p>
          <p>
            <Link to="/">View the results</Link> · <Link to="/scan-history">Scan History</Link>
          </p>
        </div>
      )}
    </div>
  );
}
