import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, FleetScreenshot, Me, ScreenshotPage, ScreenshotQuery } from "../api";
import ScreenshotCompare from "../components/ScreenshotCompare";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import TablePager from "../components/TablePager";
import { IconX } from "../components/icons";
import { formatDateTime } from "../lib/formatDate";

type KindFilter = ScreenshotQuery["kind"];

const PAGE_SIZE = 48;
// The exclusion list is remembered per browser: it is a standing "I know
// these" list, typed once, not a one-off search. The URL still wins, so a
// shared link shows exactly what its sender saw.
const EXCLUSIONS_KEY = "porttorch.screenshots.exclusions";

const splitList = (v: string | null) =>
  (v ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

function storedExclusions(): { exclude: string[]; excludeTags: string[] } {
  try {
    const parsed = JSON.parse(localStorage.getItem(EXCLUSIONS_KEY) ?? "{}");
    return {
      exclude: Array.isArray(parsed.exclude) ? parsed.exclude.filter((x: unknown) => typeof x === "string") : [],
      excludeTags: Array.isArray(parsed.excludeTags) ? parsed.excludeTags.filter((x: unknown) => typeof x === "string") : [],
    };
  } catch {
    return { exclude: [], excludeTags: [] };
  }
}

function storeExclusions(exclude: string[], excludeTags: string[]) {
  try {
    localStorage.setItem(EXCLUSIONS_KEY, JSON.stringify({ exclude, excludeTags }));
  } catch {
    // Private window or blocked storage: the list just is not remembered.
  }
}

// Every web interface and RDP login screen the fleet has captured, one
// tile per host and port. Paged and filtered on the server, so a fleet
// with a thousand captures loads one page of small previews rather than
// every full-size image at once.
export default function Screenshots({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [searchParams, setSearchParams] = useSearchParams();

  // A first visit without exclusions in the URL picks up the remembered
  // list, by writing it into the URL - so the address bar always shows
  // what is actually being filtered.
  useEffect(() => {
    if (searchParams.has("exclude") || searchParams.has("excludeTags")) return;
    const stored = storedExclusions();
    if (stored.exclude.length === 0 && stored.excludeTags.length === 0) return;
    const next = new URLSearchParams(searchParams);
    if (stored.exclude.length) next.set("exclude", stored.exclude.join(","));
    if (stored.excludeTags.length) next.set("excludeTags", stored.excludeTags.join(","));
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const query: ScreenshotQuery = useMemo(
    () => ({
      page: Math.max(1, parseInt(searchParams.get("page") ?? "1", 10) || 1),
      pageSize: PAGE_SIZE,
      q: searchParams.get("q") ?? "",
      kind: (["all", "web", "rdp", "changed"].includes(searchParams.get("kind") ?? "") ? searchParams.get("kind") : "all") as KindFilter,
      exclude: splitList(searchParams.get("exclude")),
      tags: splitList(searchParams.get("tags")),
      excludeTags: splitList(searchParams.get("excludeTags")),
    }),
    [searchParams]
  );

  const [result, setResult] = useState<ScreenshotPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [compare, setCompare] = useState<FleetScreenshot | null>(null);
  const [search, setSearch] = useState(query.q);
  const [keywordInput, setKeywordInput] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .screenshots(query)
      .then((r) => {
        if (!cancelled) setResult(r);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load screenshots");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [query]);

  // Search applies after a short pause rather than on every keystroke, so
  // typing "cisco" is one request, not five.
  useEffect(() => {
    if (search === query.q) return;
    const t = window.setTimeout(() => update({ q: search || null }), 350);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  // Any filter change goes back to page 1: page 7 of a different result is
  // an arbitrary place to land.
  function update(changes: Record<string, string | null>, keepPage = false) {
    const next = new URLSearchParams(searchParams);
    for (const [k, v] of Object.entries(changes)) {
      if (v === null || v === "") next.delete(k);
      else next.set(k, v);
    }
    if (!keepPage) next.delete("page");
    setSearchParams(next);
  }

  function setExclusions(exclude: string[], excludeTags: string[]) {
    storeExclusions(exclude, excludeTags);
    update({ exclude: exclude.join(",") || null, excludeTags: excludeTags.join(",") || null });
  }

  function addKeywords(e: FormEvent) {
    e.preventDefault();
    const added = splitList(keywordInput).filter((k) => !query.exclude.some((x) => x.toLowerCase() === k.toLowerCase()));
    if (added.length > 0) setExclusions([...query.exclude, ...added], query.excludeTags);
    setKeywordInput("");
  }

  const tagOptions = (result?.tags ?? []).map((t) => ({ id: t.tag, name: `${t.tag} (${t.count})` }));
  const counts = result?.counts;
  const filtering = Boolean(query.q || query.tags.length || query.kind !== "all");

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Screenshots</h2>
      <p className="host-meta">
        Every web interface and RDP login screen the fleet has captured, newest first - one tile per host and port,
        showing only the most recent capture of each. Click a tile to open that host.
      </p>

      <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
        <input
          placeholder="Search by host, port, page title, URL, manufacturer, text on the page..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </form>

      <div className="shot-filters">
        <form className="shot-exclude-form" onSubmit={addKeywords}>
          <label className="hide-empty-toggle">
            Hide keywords
            <input
              placeholder="e.g. cisco, ipphone, switch"
              value={keywordInput}
              onChange={(e) => setKeywordInput(e.target.value)}
              aria-label="Keywords to hide"
            />
          </label>
          <button type="submit" className="btn-icon-label" disabled={!keywordInput.trim()}>
            Hide
          </button>
        </form>
        <label className="hide-empty-toggle">
          Only tags
          <ScannerMultiSelect
            agents={tagOptions}
            selectedIds={query.tags}
            onChange={(ids) => update({ tags: ids.join(",") || null })}
            emptyLabel="Any"
          />
        </label>
        <label className="hide-empty-toggle">
          Hide tags
          <ScannerMultiSelect
            agents={tagOptions}
            selectedIds={query.excludeTags}
            onChange={(ids) => setExclusions(query.exclude, ids)}
            emptyLabel="None"
          />
        </label>
      </div>

      {(query.exclude.length > 0 || query.excludeTags.length > 0) && (
        <div className="shot-exclusions">
          <span className="host-meta">Hidden:</span>
          {query.exclude.map((k) => (
            <span key={`k-${k}`} className="chip active">
              {k}
              <button
                type="button"
                className="chip-remove"
                aria-label={`Stop hiding ${k}`}
                onClick={() => setExclusions(query.exclude.filter((x) => x !== k), query.excludeTags)}
              >
                <IconX size={11} />
              </button>
            </span>
          ))}
          {query.excludeTags.map((t) => (
            <span key={`t-${t}`} className="chip active" title="Hosts with this tag are hidden">
              tag: {t}
              <button
                type="button"
                className="chip-remove"
                aria-label={`Stop hiding tag ${t}`}
                onClick={() => setExclusions(query.exclude, query.excludeTags.filter((x) => x !== t))}
              >
                <IconX size={11} />
              </button>
            </span>
          ))}
          {result && <span className="host-meta">{result.excluded.toLocaleString()} tiles hidden</span>}
          <button type="button" className="link-button" onClick={() => setExclusions([], [])}>
            Show all again
          </button>
        </div>
      )}
      <p className="host-meta">
        A keyword hides a tile when it appears in the page title, URL, host name, the text on the screenshot, the detected
        web technologies or server headers, the manufacturer, device type or operating system, or the service on that
        port. Spacing and dashes do not matter: <code>ipphone</code> also hides "IP Phone". The hidden list is remembered in
        this browser.
      </p>

      {counts && (
        <div className="list-controls">
          <div className="filter-chips">
            {(
              [
                ["all", "All", counts.all],
                ["web", "Web", counts.web],
                ["rdp", "RDP", counts.rdp],
                ["changed", "Changed", counts.changed],
              ] as [KindFilter, string, number][]
            ).map(([key, label, count]) => (
              <button
                key={key}
                type="button"
                className={`chip ${query.kind === key ? "active" : ""}`}
                title={key === "changed" ? "The page title or HTTP status differs from the capture before it" : undefined}
                onClick={() => update({ kind: key === "all" ? null : key })}
              >
                {label} ({count.toLocaleString()})
              </button>
            ))}
          </div>
          {filtering && result && <span className="host-meta">{result.total.toLocaleString()} shown</span>}
        </div>
      )}

      {error && <p className="callout-danger">{error}</p>}

      {loading && !result ? (
        <p>Loading...</p>
      ) : !result || (result.total === 0 && result.excluded === 0 && !filtering) ? (
        <p className="empty">
          No screenshots captured yet. They are taken automatically for HTTP(S) ports (gowitness) and RDP ports during a
          scan.
        </p>
      ) : result.total === 0 ? (
        <p className="empty">No screenshots match the current search and filters.</p>
      ) : (
        <>
          <div className={`shot-grid${loading ? " shot-grid-loading" : ""}`}>
            {result.items.map((s) => (
              <Link key={`${s.kind}-${s.id}`} to={`/hosts/${s.host_id}`} className="shot-card">
                <img
                  className="shot-thumb"
                  // The small preview, not the capture itself: a page of
                  // 1920px PNGs is what made this page slow.
                  loading="lazy"
                  src={imageUrl(s.kind, s.id, "thumb")}
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
                  {s.tags.length > 0 && <span className="shot-sub shot-tags">{s.tags.join(" · ")}</span>}
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
          <TablePager
            page={result.page}
            total={result.total}
            size={result.pageSize}
            onPage={(page) => {
              update({ page: page > 1 ? String(page) : null }, true);
              window.scrollTo({ top: 0 });
            }}
          />
        </>
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

function imageUrl(kind: "web" | "rdp", id: string, variant: "image" | "thumb" = "image"): string {
  return `/api/${kind === "rdp" ? "rdp-screenshots" : "screenshots"}/${id}/${variant}`;
}
