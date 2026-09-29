import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { api, HostSummary, Me } from "../api";
import { flatPages } from "../lib/navigation";
import { ipv4PrefixToCidr, isQuickSearchShortcut, looksLikeCve, matchPages, QUICK_SEARCH_EVENT } from "../lib/quickSearch";
import { IconSearch } from "./icons";

interface Result {
  key: string;
  group: "Pages" | "Hosts" | "Search";
  label: string;
  detail?: string;
  to: string;
}

const HOST_LIMIT = 6;
const HOST_DEBOUNCE_MS = 200;

// Jump anywhere with Ctrl+K (Cmd+K on a Mac): a page by name, a host by
// IP or hostname, or a CVE across the fleet. Mounted once in App for a
// signed-in session; every page's header has a button that opens it too,
// so the shortcut is discoverable rather than folklore.
//
// Hosts come from the same GET /api/hosts the Dashboard uses, so a match
// here is exactly what the host list would show for that search -
// scanner restriction included - and the last entry always hands the
// query to the full host search rather than pretending the handful shown
// is everything.
export default function QuickSearch({ me }: { me: Me }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (isQuickSearchShortcut(e)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    }
    function onOpen() {
      setOpen(true);
    }
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener(QUICK_SEARCH_EVENT, onOpen);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener(QUICK_SEARCH_EVENT, onOpen);
    };
  }, []);

  useEffect(() => {
    if (open) {
      returnFocus.current = document.activeElement as HTMLElement | null;
      setQuery("");
      setHosts([]);
      setActive(0);
      // After the dialog has rendered.
      requestAnimationFrame(() => inputRef.current?.focus());
    } else {
      returnFocus.current?.focus?.();
    }
  }, [open]);

  // Navigating by any other means closes it too.
  useEffect(() => {
    setOpen(false);
  }, [location.pathname, location.search]);

  // What the host search is actually asked: the CIDR a partly typed IPv4
  // address names, otherwise the text as typed.
  const hostQuery = useMemo(() => ipv4PrefixToCidr(query) ?? query.trim(), [query]);

  useEffect(() => {
    const q = hostQuery;
    if (!open || q.length < 2) {
      setHosts([]);
      setHostsLoading(false);
      return;
    }
    let cancelled = false;
    setHostsLoading(true);
    const timer = setTimeout(() => {
      api
        .hosts({ q }, 1, HOST_LIMIT)
        .then((res) => {
          if (!cancelled) setHosts(res.items);
        })
        .catch(() => {
          if (!cancelled) setHosts([]);
        })
        .finally(() => {
          if (!cancelled) setHostsLoading(false);
        });
    }, HOST_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [hostQuery, open]);

  const pages = useMemo(() => flatPages(me.role), [me.role]);

  const results = useMemo<Result[]>(() => {
    const q = query.trim();
    if (!q) {
      return pages.slice(0, 8).map((p) => ({ key: `page:${p.to}`, group: "Pages", label: p.label, detail: p.section ?? undefined, to: p.to }));
    }
    const out: Result[] = [];
    if (looksLikeCve(q)) {
      out.push({
        key: "cve",
        group: "Search",
        label: `Hosts affected by ${q.toUpperCase()}`,
        detail: "host list",
        to: `/?q=${encodeURIComponent(q.toUpperCase())}`,
      });
    }
    for (const h of hosts) {
      out.push({
        key: `host:${h.id}`,
        group: "Hosts",
        label: h.hostname ? `${h.ip} · ${h.hostname}` : h.ip,
        detail: [h.scanner_agent_name ? `via ${h.scanner_agent_name}` : null, `${h.open_port_count} open port${h.open_port_count === 1 ? "" : "s"}`]
          .filter(Boolean)
          .join(" · "),
        to: `/hosts/${h.id}`,
      });
    }
    for (const p of matchPages(pages, q)) {
      out.push({ key: `page:${p.to}`, group: "Pages", label: p.label, detail: p.section ?? undefined, to: p.to });
    }
    out.push({
      key: "all",
      group: "Search",
      label: hostQuery !== q ? `All hosts in ${hostQuery}` : `Search all hosts for “${q}”`,
      detail: "host list",
      to: `/?q=${encodeURIComponent(hostQuery)}`,
    });
    return out;
  }, [query, hostQuery, hosts, pages]);

  useEffect(() => {
    setActive(0);
  }, [results.length, query]);

  if (!open) return null;

  function go(r: Result) {
    setOpen(false);
    navigate(r.to);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      setOpen(false);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (results.length ? (i + 1) % results.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (results.length ? (i - 1 + results.length) % results.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const r = results[active];
      if (r) go(r);
    }
  }

  let lastGroup: string | null = null;
  return (
    <div className="modal-backdrop quicksearch-backdrop" onClick={() => setOpen(false)}>
      <div
        className="quicksearch"
        role="dialog"
        aria-modal="true"
        aria-label="Quick search"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <div className="quicksearch-input">
          <IconSearch />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="IP, hostname, CVE or page..."
            aria-label="Search"
            aria-controls="quicksearch-results"
            aria-activedescendant={results[active] ? `qs-${active}` : undefined}
            role="combobox"
            aria-expanded="true"
            autoComplete="off"
            spellCheck={false}
          />
          {hostsLoading && <span className="host-meta">searching...</span>}
        </div>
        <ul id="quicksearch-results" className="quicksearch-results" role="listbox">
          {results.map((r, i) => {
            const heading = r.group !== lastGroup ? r.group : null;
            lastGroup = r.group;
            return (
              <li key={r.key} role="presentation">
                {heading && <div className="quicksearch-group">{heading}</div>}
                <div
                  id={`qs-${i}`}
                  role="option"
                  aria-selected={i === active}
                  className={`quicksearch-item${i === active ? " active" : ""}`}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => go(r)}
                >
                  <span>{r.label}</span>
                  {r.detail && <span className="host-meta">{r.detail}</span>}
                </div>
              </li>
            );
          })}
        </ul>
        <div className="quicksearch-footer host-meta">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> move
          </span>
          <span>
            <kbd>Enter</kbd> open
          </span>
          <span>
            <kbd>Esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}
