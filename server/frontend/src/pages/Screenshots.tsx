import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, FleetScreenshot, Me } from "../api";
import ScreenshotCompare from "../components/ScreenshotCompare";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

type KindFilter = "all" | "web" | "rdp" | "changed";

export default function Screenshots({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [shots, setShots] = useState<FleetScreenshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");
  const [compare, setCompare] = useState<FleetScreenshot | null>(null);

  useEffect(() => {
    api
      .screenshots()
      .then(setShots)
      .finally(() => setLoading(false));
  }, []);

  const trimmed = query.trim().toLowerCase();
  const filtered = shots.filter((s) => {
    if (kind === "changed" ? !s.changed : kind !== "all" && s.kind !== kind) return false;
    if (!trimmed) return true;
    return (
      s.host_ip.toLowerCase().includes(trimmed) ||
      (s.host_hostname ?? "").toLowerCase().includes(trimmed) ||
      (s.page_title ?? "").toLowerCase().includes(trimmed) ||
      (s.url ?? "").toLowerCase().includes(trimmed) ||
      String(s.port).includes(trimmed)
    );
  });

  const webCount = shots.filter((s) => s.kind === "web").length;
  const rdpCount = shots.length - webCount;
  const changedCount = shots.filter((s) => s.changed).length;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Screenshots</h2>
      <p className="host-meta">
        Every web interface and RDP login screen the fleet has captured, newest first - one tile per host and port,
        showing only the most recent capture of each. Click a tile to open that host.
      </p>

      {shots.length > 0 && (
        <>
          <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
            <input
              placeholder="Search by host, port, page title, or URL..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </form>
          <div className="list-controls">
            <div className="filter-chips">
              <button type="button" className={`chip ${kind === "all" ? "active" : ""}`} onClick={() => setKind("all")}>
                All ({shots.length})
              </button>
              <button type="button" className={`chip ${kind === "web" ? "active" : ""}`} onClick={() => setKind("web")}>
                Web ({webCount})
              </button>
              <button type="button" className={`chip ${kind === "rdp" ? "active" : ""}`} onClick={() => setKind("rdp")}>
                RDP ({rdpCount})
              </button>
              <button
                type="button"
                className={`chip ${kind === "changed" ? "active" : ""}`}
                title="The page title or HTTP status differs from the capture before it"
                onClick={() => setKind("changed")}
              >
                Changed ({changedCount})
              </button>
            </div>
          </div>
          {(trimmed || kind !== "all") && <p className="host-meta">{filtered.length} of {shots.length} shown</p>}
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : shots.length === 0 ? (
        <p className="empty">
          No screenshots captured yet. They are taken automatically for HTTP(S) ports (gowitness) and RDP ports
          during a scan.
        </p>
      ) : filtered.length === 0 ? (
        <p className="empty">No screenshots match the current search/filter.</p>
      ) : (
        <div className="shot-grid">
          {filtered.map((s) => (
            <Link key={`${s.kind}-${s.id}`} to={`/hosts/${s.host_id}`} className="shot-card">
              <img
                className="shot-thumb"
                // Loaded lazily: a fleet with hundreds of captures would
                // otherwise fetch every image the moment the page opens.
                loading="lazy"
                src={imageUrl(s.kind, s.id)}
                alt={`${s.host_hostname || s.host_ip}:${s.port}`}
              />
              <div className="shot-meta">
                <span className="shot-title">
                  {s.page_title || (s.kind === "rdp" ? "RDP login screen" : s.url) || `${s.host_ip}:${s.port}`}
                </span>
                <span className="shot-sub">
                  {s.host_hostname || s.host_ip} : {s.port}
                  {s.kind === "rdp" && " · RDP"}
                  {s.http_status !== null && s.http_status !== undefined && ` · HTTP ${s.http_status}`}
                </span>
                <span className="shot-sub">
                  {formatDateTime(s.captured_at, me.preferences)}
                  {s.changed && (
                    // Its own button, not part of the tile's link: the
                    // tile opens the host, which is what the page is for.
                    <button
                      type="button"
                      className="link-button shot-changed"
                      title="This capture differs from the one before it - compare them"
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setCompare(s);
                      }}
                    >
                      changed
                    </button>
                  )}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}

      {compare && compare.previous && (
        <ScreenshotCompare
          title={`${compare.host_hostname || compare.host_ip}:${compare.port}`}
          kind={compare.kind}
          current={compare}
          previous={compare.previous}
          preferences={me.preferences}
          onClose={() => setCompare(null)}
          footer={
            <p>
              <Link to={`/hosts/${compare.host_id}`}>Open this host</Link>
            </p>
          }
        />
      )}
    </div>
  );
}

function imageUrl(kind: "web" | "rdp", id: string): string {
  return `/api/${kind === "rdp" ? "rdp-screenshots" : "screenshots"}/${id}/image`;
}
