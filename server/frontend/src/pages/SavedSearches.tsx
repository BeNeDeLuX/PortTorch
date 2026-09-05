import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, Me, SavedSearch, SavedSearchMatches } from "../api";
import { IconSearch, IconTrash } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

// Saved searches used to live only as a row of chips in the dashboard
// sidebar - enough to re-run one, and nothing else. They also drive the
// saved_search.match webhook, so "which of these is actually firing, and
// at what" was a question with no answer anywhere in the UI.
export default function SavedSearches({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [searches, setSearches] = useState<SavedSearch[]>([]);
  const [matches, setMatches] = useState<Record<string, SavedSearchMatches>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const [list, matchList] = await Promise.all([
        api.savedSearches(),
        api.savedSearchMatches().catch(() => [] as SavedSearchMatches[]),
      ]);
      setSearches(list);
      setMatches(Object.fromEntries(matchList.map((m) => [m.savedSearchId, m])));
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(search: SavedSearch) {
    if (!window.confirm(`Delete the saved search "${search.name}"? Any saved_search.match alerts it fires stop with it.`)) {
      return;
    }
    await api.deleteSavedSearch(search.id);
    await load();
  }

  // The stored filters are exactly the dashboard's own query string, so
  // the link back is the object itself rather than a translation.
  function searchHref(search: SavedSearch): string {
    return `/?${new URLSearchParams(search.filters as Record<string, string>).toString()}`;
  }

  function describe(search: SavedSearch): string {
    const entries = Object.entries(search.filters as Record<string, string>).filter(([, v]) => v !== "");
    if (entries.length === 0) return "no filters - matches every host";
    return entries.map(([k, v]) => `${k}: ${v}`).join(" · ");
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Saved Searches</h2>
      <p className="empty">
        A saved search is a dashboard filter you kept, and it is also an alert: the checker re-runs each one every few
        minutes and fires a <code>saved_search.match</code> webhook for hosts that have <em>newly</em> started matching.
        The hosts below are what each search matched at the last check - a host listed here has already been reported
        and will not alert again, which is exactly what makes this list worth reading. Create one from the Scan Results
        page, by saving the filters you currently have applied.
      </p>

      {loading ? (
        <p>Loading...</p>
      ) : searches.length === 0 ? (
        <p className="empty">
          No saved searches yet. Filter the host list on Scan Results the way you want, then use "Save this search".
        </p>
      ) : (
        <div className="settings-grid">
          {searches.map((search) => {
            const match = matches[search.id];
            const count = match?.matchCount ?? 0;
            return (
              <section key={search.id} className="settings-card">
                <h3 className="settings-card-title">{search.name}</h3>
                <div className="settings-card-desc">{describe(search)}</div>

                <p className="settings-state">
                  {count === 0 ? (
                    "Matching no hosts at the last check."
                  ) : (
                    <>
                      Matching <strong>{count.toLocaleString()}</strong> host{count === 1 ? "" : "s"} at the last check.
                    </>
                  )}
                </p>

                {match && match.hosts.length > 0 && (
                  <ul className="settings-list">
                    {match.hosts.map((h) => (
                      <li key={h.id}>
                        <Link to={`/hosts/${h.id}`} className="settings-list-main">
                          {h.hostname ? `${h.ip} (${h.hostname})` : h.ip}
                        </Link>
                        <span className="empty">last seen {formatDateTime(h.lastSeenAt, me.preferences)}</span>
                      </li>
                    ))}
                    {count > match.hosts.length && (
                      <li className="empty">and {(count - match.hosts.length).toLocaleString()} more</li>
                    )}
                  </ul>
                )}

                <p className="settings-state">
                  Saved by {search.created_by ?? "unknown"} on {formatDateTime(search.created_at, me.preferences)}
                </p>

                <div className="inline-actions">
                  <Link to={searchHref(search)} className="btn-icon-label">
                    <IconSearch /> Open in Scan Results
                  </Link>
                  <button type="button" className="btn-icon-label" onClick={() => handleDelete(search)}>
                    <IconTrash /> Delete
                  </button>
                </div>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}
