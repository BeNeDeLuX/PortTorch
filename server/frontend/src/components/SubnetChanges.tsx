import { FormEvent, ReactNode, useEffect, useState } from "react";
import { Link } from "react-router";
import { api, Me, SubnetChangeHost, SubnetChangePort, SubnetChangesResult } from "../api";
import { formatDateTime } from "../lib/formatDate";
import { IconCheck, IconSearch } from "./icons";

const DAY_MS = 24 * 60 * 60 * 1000;
const PRESETS: [string, number][] = [
  ["24 hours", 1],
  ["7 days", 7],
  ["30 days", 30],
  ["90 days", 90],
];

// <input type="datetime-local"> has no timezone: it is the browser's local
// time, so it is formatted and parsed with plain Date methods - the same
// convention as the Digest page's range.
function toLocalInputValue(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// What changed in one network between two moments - the network-sized
// counterpart to Host Detail's comparison of two scans of one host.
export default function SubnetChanges({
  me,
  network: initialNetwork,
  scannerAgentIds,
  hideRetired,
}: {
  me: Me;
  network: string;
  scannerAgentIds: string[];
  hideRetired: boolean;
}) {
  const [network, setNetwork] = useState(initialNetwork);
  const [fromInput, setFromInput] = useState(() => toLocalInputValue(new Date(Date.now() - 7 * DAY_MS)));
  const [toInput, setToInput] = useState(() => toLocalInputValue(new Date()));
  const [result, setResult] = useState<SubnetChangesResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [baselineMessage, setBaselineMessage] = useState<string | null>(null);
  const canEdit = me.role === "admin" || me.role === "operator";

  async function run(net = network, from = fromInput, to = toInput) {
    if (!net.trim()) return;
    setLoading(true);
    setError(null);
    try {
      setResult(
        await api.subnetChanges(
          net.trim(),
          new Date(from).toISOString(),
          new Date(to).toISOString(),
          scannerAgentIds,
          hideRetired
        )
      );
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Could not compare");
    } finally {
      setLoading(false);
    }
  }

  // A network handed over from the map runs straight away; the scanner
  // and retired filters above re-run whatever is currently shown.
  useEffect(() => {
    setNetwork(initialNetwork);
    if (initialNetwork) run(initialNetwork);
  }, [initialNetwork]);

  useEffect(() => {
    if (result) run();
  }, [scannerAgentIds, hideRetired]);

  // A baseline scoped the way this view is: to the one scanner filtered
  // on, or to every scanner when the filter is empty or names several.
  async function approveAsBaseline() {
    if (!result) return;
    setBaselineMessage(null);
    try {
      await api.createBaseline(result.network, scannerAgentIds.length === 1 ? scannerAgentIds[0] : null, null);
      setBaselineMessage(`The current state of ${result.network} is now its baseline - see the Baselines page.`);
    } catch (err) {
      setBaselineMessage(err instanceof Error ? err.message : "Could not create the baseline");
    }
  }

  function preset(days: number) {
    const to = toLocalInputValue(new Date());
    const from = toLocalInputValue(new Date(Date.now() - days * DAY_MS));
    setFromInput(from);
    setToInput(to);
    run(network, from, to);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    run();
  }

  return (
    <>
      <p className="host-meta">
        Compares one network between two moments: hosts first found in between, hosts known before that no scan reported
        in between, and ports that opened or closed on hosts that were already there. Each moment is reconstructed from
        the scan history the same way the rest of the dashboard shows the current state.
      </p>
      <form className="list-controls subnet-changes-form" onSubmit={handleSubmit}>
        <div className="list-controls-filters">
          <label className="hide-empty-toggle">
            Network
            <input
              value={network}
              onChange={(e) => setNetwork(e.target.value)}
              placeholder="10.46.0.0/16 or 10.46"
              aria-label="Network to compare"
            />
          </label>
          <label className="hide-empty-toggle">
            From
            <input type="datetime-local" value={fromInput} onChange={(e) => setFromInput(e.target.value)} />
          </label>
          <label className="hide-empty-toggle">
            To
            <input type="datetime-local" value={toInput} onChange={(e) => setToInput(e.target.value)} />
          </label>
          <button type="submit" className="btn-icon-label" disabled={loading || !network.trim()}>
            <IconSearch /> {loading ? "Comparing..." : "Compare"}
          </button>
        </div>
        <div className="filter-chips">
          <span className="empty">Last</span>
          {PRESETS.map(([label, days]) => (
            <button key={label} type="button" className="chip" onClick={() => preset(days)} disabled={!network.trim()}>
              {label}
            </button>
          ))}
        </div>
      </form>

      {error && <p className="callout-danger">{error}</p>}
      {!result && !error && !loading && (
        <p className="empty">Enter a network, or open one from the map with its "changes" link.</p>
      )}

      {result && canEdit && (
        <p className="inline-actions">
          <button type="button" className="btn-icon-label" onClick={approveAsBaseline}>
            <IconCheck /> Approve {result.network} as baseline
          </button>
          {baselineMessage && <span className="host-meta">{baselineMessage}</span>}
        </p>
      )}
      {result && <ChangesReport result={result} me={me} />}
    </>
  );
}

// The tiles and four lists of a comparison, shared by the Changes view
// and a baseline's detail on the Baselines page.
export function ChangesReport({ result, me }: { result: SubnetChangesResult; me: Me }) {
  return (
    <>
      <div className="stat-tiles">
        <Tile label={`Hosts on ${formatDateTime(result.from, me.preferences)}`} value={result.hostsBefore} />
        <Tile label={`Hosts on ${formatDateTime(result.to, me.preferences)}`} value={result.hostsAfter} />
        <Tile label="Scans in between" value={result.scansInPeriod} />
      </div>
      {result.scansInPeriod === 0 && (
        <p className="callout-warning">
          No scan reported anything in {result.network} during this period, so every host known before it is listed
          as not seen - that says nothing about whether they are still there.
        </p>
      )}

      <ChangeSection
        title="New hosts"
        empty="No host was first found in this period."
        list={result.newHosts}
        limit={result.limit}
        headers={["Host", "Open ports", "Scanner", "First seen"]}
      >
        {result.newHosts.items.map((h) => (
          <HostRow key={h.hostId} host={h} me={me} date={h.firstSeenAt} />
        ))}
      </ChangeSection>

      <ChangeSection
        title="Not seen in this period"
        note="Known before the period, but no scan reported them during it. Either gone, or not scanned - the number of scans above tells you which is likely."
        empty="Every host known before the period was reported again during it."
        list={result.unseenHosts}
        limit={result.limit}
        headers={["Host", "Open ports when last seen", "Scanner", "Last seen"]}
      >
        {result.unseenHosts.items.map((h) => (
          <HostRow key={h.hostId} host={h} me={me} date={h.lastSeenAt} />
        ))}
      </ChangeSection>

      <ChangeSection
        title="Ports opened"
        note="On hosts that already existed when the period began. A new host's ports are listed with it above."
        empty="No port opened on an existing host."
        list={result.openedPorts}
        limit={result.limit}
        headers={["Host", "Port", "Service", "Seen open"]}
      >
        {result.openedPorts.items.map((p) => (
          <PortRow key={`${p.hostId}-${p.port}-${p.protocol}`} port={p} me={me} />
        ))}
      </ChangeSection>

      <ChangeSection
        title="Ports closed"
        note="Only ports a scan recorded as closed. A port that silently stopped answering keeps its last open record, the same as everywhere else in the dashboard."
        empty="No port was recorded closed."
        list={result.closedPorts}
        limit={result.limit}
        headers={["Host", "Port", "Service", "Recorded closed"]}
      >
        {result.closedPorts.items.map((p) => (
          <PortRow key={`${p.hostId}-${p.port}-${p.protocol}`} port={p} me={me} />
        ))}
      </ChangeSection>
    </>
  );
}

function Tile({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-value">{value.toLocaleString()}</div>
      <div className="stat-tile-label">{label}</div>
    </div>
  );
}

function ChangeSection({
  title,
  note,
  empty,
  list,
  limit,
  headers,
  children,
}: {
  title: string;
  headers: string[];
  note?: string;
  empty: string;
  list: { items: unknown[]; truncated: boolean };
  limit: number;
  children: ReactNode;
}) {
  return (
    <section className="subnet-changes-section">
      <h3>
        {title} <span className="host-meta">({list.items.length.toLocaleString()}{list.truncated ? "+" : ""})</span>
      </h3>
      {note && <p className="host-meta">{note}</p>}
      {list.truncated && (
        <p className="callout-warning">Showing the first {limit.toLocaleString()}. Narrow the network or the period to see the rest.</p>
      )}
      {list.items.length === 0 ? (
        <p className="empty">{empty}</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                {headers.map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>{children}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function HostRow({ host, me, date }: { host: SubnetChangeHost; me: Me; date: string | null }) {
  return (
    <tr>
      <td>
        <Link className="port-link" to={`/hosts/${host.hostId}`}>
          {host.ip}
        </Link>
        {host.hostname && <span className="host-meta"> {host.hostname}</span>}
      </td>
      <td>{host.openPorts.length > 0 ? host.openPorts.join(", ") : <span className="host-meta">no open ports</span>}</td>
      <td className="host-meta">{host.scannerAgentName ?? "?"}</td>
      <td className="host-meta">{date ? formatDateTime(date, me.preferences) : "-"}</td>
    </tr>
  );
}

function PortRow({ port, me }: { port: SubnetChangePort; me: Me }) {
  return (
    <tr>
      <td>
        <Link className="port-link" to={`/hosts/${port.hostId}`}>
          {port.ip}
        </Link>
        {port.hostname && <span className="host-meta"> {port.hostname}</span>}
      </td>
      <td>
        {port.port}/{port.protocol}
      </td>
      <td className="host-meta">{port.serviceName ?? "-"}</td>
      <td className="host-meta">{formatDateTime(port.observedAt, me.preferences)}</td>
    </tr>
  );
}
