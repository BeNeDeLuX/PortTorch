import { FormEvent, useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { AdhocScanResult, api, Me, NSEProfileSelection, NucleiProfileSelection, ScanPriority, ScannerAgent } from "../api";
import { IconPlay } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScanEstimateButton from "../components/ScanEstimate";
import ScanProfilePicker from "../components/ScanProfilePicker";
import NucleiProfilePicker from "../components/NucleiProfilePicker";
import ScanPriorityPicker from "../components/ScanPriorityPicker";
import ScanRateSupportNote from "../components/ScanRateSupportNote";
import PortSpecHint from "../components/PortSpecHint";
import { MAX_TARGET_SPEC_LENGTH, parseTargetList } from "../lib/targetList";
import { parseTagList } from "../lib/scanTags";
import { formatDateTime } from "../lib/formatDate";

// Router state Scan History hands off when the operator clicks its own
// "Rescan" button - see that page for why only these three fields travel
// (profile/nuclei/tags/priority are deliberately picked fresh here rather
// than replayed, the same as every other Rescan trigger point in this
// app: RescanModal always shows its own picker rather than reproducing a
// host's last-used profile).
interface RescanNavState {
  targetSpec?: string;
  portSpec?: string;
  scannerAgentId?: string;
}

// A one-shot "scan this right now" page - Schedule Scans minus all the
// interval/cron/run-at machinery, since an ad-hoc scan has no schedule at
// all: submitting fires a single scan_requests row that the chosen
// scanner picks up on its very next poll. Not admin-gated (requireOperator
// on the API side too), same access tier as the Rescan button.
export default function AdhocScans({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const location = useLocation();
  // Read once, on mount - a plain useState initializer, matching how
  // HostDetail reads its own router-state hand-off. Re-visiting this page
  // later (a fresh navigation with no state) starts blank as normal.
  const navState = (location.state ?? null) as RescanNavState | null;

  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [loading, setLoading] = useState(true);

  const [scannerAgentId, setScannerAgentId] = useState(navState?.scannerAgentId ?? "");
  const [targetSpec, setTargetSpec] = useState(navState?.targetSpec ?? "");
  // What the last uploaded file produced, shown under the field - a spec
  // of a few thousand addresses is not something anyone reads back out of
  // an input, so the count is what tells them it worked.
  const [listSummary, setListSummary] = useState<string | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [portSpec, setPortSpec] = useState(navState?.portSpec ?? "");
  const [profile, setProfile] = useState<NSEProfileSelection>({ kind: "default" });
  const [nucleiProfile, setNucleiProfile] = useState<NucleiProfileSelection>({ kind: "off" });
  const [masscanRate, setMasscanRate] = useState("");
  // Pre-selected High rather than the column's own 'normal' default:
  // someone typing a target into this form is by definition waiting on
  // the result, and the whole point of the page is "scan this now" - so
  // it should get ahead of a scheduled sweep that happens to be queued.
  // The API itself still defaults to 'normal' when the field is omitted,
  // keeping the External API's own ad-hoc endpoint unchanged.
  const [priority, setPriority] = useState<ScanPriority>("high");
  const [tags, setTags] = useState("");

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
      // Also re-defaults when a pre-filled scanner (from a Rescan hand-off)
      // no longer exists among the active agents - deleted or revoked
      // since that scan ran - rather than leaving the <select> pointed at
      // an id with no matching option.
      const stillValid = scannerAgentId !== "" && activeAgents.some((a) => a.id === scannerAgentId);
      if (activeAgents.length > 0 && !stillValid) {
        setScannerAgentId(activeAgents[0].id);
      }
    } finally {
      setLoading(false);
    }
  }

  // The file never leaves the browser: it is parsed here into exactly the
  // comma-separated spec someone could have typed, so everything else on
  // this page - Estimate time, the profile pickers, priority - keeps
  // working without knowing a file was involved.
  async function handleTargetFile(file: File) {
    setListError(null);
    setListSummary(null);
    const result = parseTargetList(await file.text());

    // Fail closed rather than loading the readable half: a file that is
    // partly junk usually means the wrong column or the wrong file, and
    // half a target list submitted silently is worse than none.
    if (result.errors.length > 0) {
      const shown = result.errors
        .slice(0, 3)
        .map((e) => `line ${e.line}: "${e.value}"`)
        .join(", ");
      const more = result.errors.length > 3 ? ` (and ${result.errors.length - 3} more)` : "";
      const n = result.errors.length;
      setListError(
        `${file.name} has ${n === 1 ? "an entry that is" : `${n} entries that are`} not an address, CIDR, range or qualified hostname - ${shown}${more}. Nothing was loaded.`
      );
      return;
    }
    if (result.entries.length === 0) {
      setListError(`${file.name} contains no addresses.`);
      return;
    }
    // The scanner passes the whole spec to masscan as one argument, and
    // Linux caps a single argument - see MAX_TARGET_SPEC_LENGTH. Caught
    // here rather than as an unexplained scan failure an hour later.
    if (result.spec.length > MAX_TARGET_SPEC_LENGTH) {
      setListError(`${file.name} is too long for one scan: ${result.entries.length} addresses come to ${Math.round(result.spec.length / 1024)} KB, and the limit is ${MAX_TARGET_SPEC_LENGTH / 1024} KB. Split it, or use CIDRs where the list covers whole subnets.`);
      return;
    }

    setTargetSpec(result.spec);
    const dupes = result.duplicates > 0 ? `, ${result.duplicates} duplicate${result.duplicates === 1 ? "" : "s"} dropped` : "";
    setListSummary(`${result.entries.length} address${result.entries.length === 1 ? "" : "es"} loaded from ${file.name}${dupes}.`);
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
        priority,
        ...(masscanRate.trim() ? { masscanRate: Number(masscanRate) } : {}),
        ...(tags.trim() ? { tags: parseTagList(tags) } : {}),
      });
      setLastResult(result);
      setTargetSpec("");
      setListSummary(null);
      setListError(null);
      setPortSpec("");
      setProfile({ kind: "default" });
      setNucleiProfile({ kind: "off" });
      setPriority("high");
      setMasscanRate("");
      setTags("");
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
      {navState && (
        <p className="callout-success">
          Target, ports and scanner pre-filled from Scan History - the scan profile, nuclei profile, tags and
          priority are left for you to pick fresh, same as any other rescan.
        </p>
      )}

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
              placeholder="192.168.1.0/24, 2001:db8::1, web1.internal, or a mix"
              value={targetSpec}
              onChange={(e) => {
                setTargetSpec(e.target.value);
                // Typing over a loaded list makes the summary a
                // statement about something that is no longer there.
                setListSummary(null);
                setListError(null);
              }}
            />
          </label>
          {/* Same plain labelled file input as Import Scan and the
              settings cards, rather than a styled button - nothing here
              needs a new control. */}
          <label>
            Or load a list from a file
            <input
              type="file"
              accept=".txt,.csv,.lst,text/plain,text/csv"
              onChange={(e) => {
                const file = e.target.files?.[0];
                // Clearing the input is what lets the same file be picked
                // again after an error - otherwise change never fires.
                e.target.value = "";
                if (file) void handleTargetFile(file);
              }}
            />
          </label>
          {listSummary && (
            <p className="empty">
              {listSummary}{" "}
              <button
                type="button"
                className="link-button"
                onClick={() => {
                  setTargetSpec("");
                  setListSummary(null);
                }}
              >
                Clear
              </button>
            </p>
          )}
          {listError && <p className="callout-warning">{listError}</p>}
          <p className="empty">
            DNS hostnames are resolved by the scanner itself, and can be mixed freely with IPs, CIDRs and ranges in
            one comma-separated list. Each resolved name also becomes that host's TLS SNI / screenshot hostname, the
            same effect as setting its "probe hostname" by hand. A name that does not resolve fails the scan rather
            than being skipped. A file can hold one entry per line or a comma-separated list, with <code>#</code>{" "}
            comments - it is read here in the browser and becomes exactly the target you see in the field, so you can
            still edit it before starting.
          </p>
          <label>
            Ports
            <input placeholder="1-1000" value={portSpec} onChange={(e) => setPortSpec(e.target.value)} />
          </label>
          <PortSpecHint />
          <label>
            Scan profile
            <ScanProfilePicker value={profile} onChange={setProfile} />
          </label>
          <label>
            Nuclei profile
            <NucleiProfilePicker value={nucleiProfile} onChange={setNucleiProfile} />
          </label>
          <label>
            Queue priority
            <ScanPriorityPicker value={priority} onChange={setPriority} />
          </label>
          <label>
            Scan rate (optional)
            <input
              type="number"
              min={1}
              placeholder="scanner default"
              value={masscanRate}
              onChange={(e) => setMasscanRate(e.target.value)}
            />
          </label>
          <ScanRateSupportNote agent={agents.find((a) => a.id === scannerAgentId)} rate={masscanRate} />
          <p className="empty">
            Packets per second for the masscan discovery pass. Leave blank to use whatever the chosen scanner has
            configured (default 1000). Lower it for fragile or sensitive network segments; only affects this scan.
          </p>
          <label>
            Tags (optional)
            <input placeholder="Q3-Audit, external-range" value={tags} onChange={(e) => setTags(e.target.value)} />
          </label>
          <p className="empty">
            Comma-separated. Applied to every host this scan actually finds, so "find exactly what this scan found"
            is a tag filter on the Dashboard afterwards - filterable, removable, and shown alongside any tag added by
            hand.
          </p>

          <div className="inline-actions">
            <button type="submit" className="btn-icon-label" disabled={submitting}>
              <IconPlay /> {submitting ? "Queuing..." : "Start scan"}
            </button>
            <ScanEstimateButton
              targetSpec={targetSpec}
              portSpec={portSpec}
              scannerAgentId={scannerAgentId}
              masscanRate={masscanRate}
            />
          </div>
        </form>
      )}

      {error && <p className="callout-danger">{error}</p>}

      {lastResult && (
        <p className="callout-success">
          Scan queued for {lastResult.scannerAgentName} at {formatDateTime(lastResult.created_at, me.preferences)}.
          Profile: {lastResult.nse_profile_label ?? "Default"}
          {lastResult.nuclei_profile_label ? `, Nuclei: ${lastResult.nuclei_profile_label}` : ""}, priority:{" "}
          {lastResult.priority}
          {lastResult.tags && lastResult.tags.length > 0 ? `, tags: ${lastResult.tags.join(", ")}` : ""}.
        </p>
      )}
    </div>
  );
}
