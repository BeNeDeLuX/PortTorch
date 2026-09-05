import { FormEvent, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import {
  ActiveScanJob,
  api,
  Facets,
  HostFilters,
  HostListResult,
  HostSummary,
  Me,
  NSEProfileSelection,
  NucleiProfileSelection,
  ScanPriority,
  SavedSearch,
  ScannerAgent,
} from "../api";
import ExportModal from "../components/ExportModal";
import {
  IconArchive,
  IconBookmark,
  IconDownload,
  IconInfo,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconStop,
  IconTrash,
  IconWarning,
  IconX,
} from "../components/icons";
import PageHeader from "../components/PageHeader";
import RescanModal from "../components/RescanModal";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import ScanProgressModal from "../components/ScanProgressModal";
import { elapsedLabel } from "../lib/elapsed";
import { formatDateTime } from "../lib/formatDate";
import { cveSeverityClass } from "../lib/cveSeverity";
import { STATUS_LABEL, useFleetHealth } from "../lib/useFleetHealth";

const PAGE_SIZE = 50;

function parseCommaList(value: string | null): string[] {
  if (!value) return [];
  return value.split(",").map((v) => v.trim()).filter(Boolean);
}

// A leading "-" means "exclude", in the URL exactly as the server reads
// it (?port=443,-53) - one parameter carrying both directions, so a
// filter looks the same in the address bar, in a saved search and in the
// External API. A bare "-" is dropped rather than becoming an empty
// exclusion, matching the server's own splitNegated.
function splitNegated(values: string[]): { include: string[]; exclude: string[] } {
  const include: string[] = [];
  const exclude: string[] = [];
  for (const value of values) {
    if (value.startsWith("-")) {
      const rest = value.slice(1).trim();
      if (rest) exclude.push(rest);
    } else {
      include.push(value);
    }
  }
  return { include, exclude };
}

// An empty list has to become undefined, not [], or the filter would stay
// in the URL as an empty parameter and read as "still filtered".
function orUndefined<T>(values: T[]): T[] | undefined {
  return values.length ? values : undefined;
}

function filtersFromSearchParams(searchParams: URLSearchParams): HostFilters {
  const toPorts = (values: string[]) => values.map((p) => Number(p)).filter((p) => !Number.isNaN(p));
  const port = splitNegated(parseCommaList(searchParams.get("port")));
  const service = splitNegated(parseCommaList(searchParams.get("service")));
  const tag = splitNegated(parseCommaList(searchParams.get("tag")));
  const ports = toPorts(port.include);
  const excludePorts = toPorts(port.exclude);
  const services = service.include;
  const tags = tag.include;
  const scannerAgentIds = parseCommaList(searchParams.get("scannerAgentId"));
  return {
    q: searchParams.get("q") ?? undefined,
    ports: ports.length ? ports : undefined,
    services: services.length ? services : undefined,
    tags: tags.length ? tags : undefined,
    excludePorts: excludePorts.length ? excludePorts : undefined,
    excludeServices: service.exclude.length ? service.exclude : undefined,
    excludeTags: tag.exclude.length ? tag.exclude : undefined,
    osFamily: searchParams.get("osFamily") ?? undefined,
    deviceType: searchParams.get("deviceType") ?? undefined,
    hideEmpty: searchParams.get("hideEmpty") === "true" || undefined,
    hideRetired: searchParams.get("hideRetired") === "true" || undefined,
    hasScreenshot: searchParams.get("hasScreenshot") === "true" || undefined,
    hasStalePorts: searchParams.get("hasStalePorts") === "true" || undefined,
    lastSeenAfter: searchParams.get("lastSeenAfter") ?? undefined,
    lastSeenBefore: searchParams.get("lastSeenBefore") ?? undefined,
    scannerAgentIds: scannerAgentIds.length ? scannerAgentIds : undefined,
  };
}

type ViewMode = "grid" | "table";
type ColumnKey = "hostname" | "open_port_count" | "last_seen_at" | "screenshot" | "device" | "mac" | "scanner" | "risk";
type SortKey = "ip" | ColumnKey;
type SortDirection = "asc" | "desc";

const TOGGLEABLE_COLUMNS: Array<{ key: ColumnKey; label: string }> = [
  { key: "hostname", label: "Hostname" },
  { key: "open_port_count", label: "Open Ports" },
  { key: "last_seen_at", label: "Last Seen" },
  { key: "screenshot", label: "Screenshot" },
  { key: "device", label: "OS/Device" },
  { key: "mac", label: "MAC" },
  { key: "scanner", label: "Scanner" },
  { key: "risk", label: "Risk (CVEs)" },
];

interface TablePrefs {
  view: ViewMode;
  columns: ColumnKey[];
  sortKey: SortKey;
  sortDirection: SortDirection;
}

const TABLE_PREFS_KEY = "porttorch.dashboard.tablePrefs";

const DEFAULT_TABLE_PREFS: TablePrefs = {
  view: "grid",
  columns: TOGGLEABLE_COLUMNS.map((c) => c.key),
  sortKey: "last_seen_at",
  sortDirection: "desc",
};

function loadTablePrefs(): TablePrefs {
  try {
    const raw = localStorage.getItem(TABLE_PREFS_KEY);
    if (!raw) return DEFAULT_TABLE_PREFS;
    return { ...DEFAULT_TABLE_PREFS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_TABLE_PREFS;
  }
}

// Expands an IPv6 address's "::" shorthand (at most one per address) into
// its full 8 hextet groups, parsed as numbers, so they can be compared
// group-by-group - e.g. "2001:db8::1" -> [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].
function expandIPv6Groups(ip: string): number[] {
  const shorthandIdx = ip.indexOf("::");
  if (shorthandIdx === -1) {
    return ip.split(":").map((g) => parseInt(g || "0", 16));
  }
  const left = ip.slice(0, shorthandIdx);
  const right = ip.slice(shorthandIdx + 2);
  const leftGroups = left ? left.split(":") : [];
  const rightGroups = right ? right.split(":") : [];
  const missing = Math.max(8 - leftGroups.length - rightGroups.length, 0);
  return [...leftGroups, ...new Array(missing).fill("0"), ...rightGroups].map((g) => parseInt(g || "0", 16));
}

// IPv4 is compared octet-by-octet (numeric, so "10.0.0.2" sorts before
// "10.0.0.10" - a plain string compare would get that backwards). IPv6
// addresses (contain ":") get the equivalent hextet-by-hextet numeric
// compare via expandIPv6Groups. The two families have no natural shared
// ordering, so mixed comparisons just put every IPv4 address before every
// IPv6 one, consistently.
function compareIp(a: string, b: string): number {
  const aIsV6 = a.includes(":");
  const bIsV6 = b.includes(":");
  if (aIsV6 !== bIsV6) return aIsV6 ? 1 : -1;

  if (aIsV6) {
    const ga = expandIPv6Groups(a);
    const gb = expandIPv6Groups(b);
    for (let i = 0; i < 8; i++) {
      if ((ga[i] ?? 0) !== (gb[i] ?? 0)) return (ga[i] ?? 0) - (gb[i] ?? 0);
    }
    return 0;
  }

  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 4; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

function sortHosts(hosts: HostSummary[], sortKey: SortKey, direction: SortDirection): HostSummary[] {
  const sign = direction === "asc" ? 1 : -1;
  return [...hosts].sort((a, b) => {
    switch (sortKey) {
      case "ip":
        return sign * compareIp(a.ip, b.ip);
      case "hostname":
        return sign * (a.hostname ?? "").localeCompare(b.hostname ?? "");
      case "open_port_count":
        return sign * (a.open_port_count - b.open_port_count);
      case "last_seen_at":
        return sign * (new Date(a.last_seen_at).getTime() - new Date(b.last_seen_at).getTime());
      case "screenshot":
        return sign * (a.thumbnail_kind ?? "").localeCompare(b.thumbnail_kind ?? "");
      case "device":
        return sign * (a.device_type ?? a.os_family ?? "").localeCompare(b.device_type ?? b.os_family ?? "");
      case "mac":
        return sign * (a.mac_address ?? "").localeCompare(b.mac_address ?? "");
      case "scanner":
        return sign * (a.scanner_agent_name ?? "").localeCompare(b.scanner_agent_name ?? "");
      case "risk":
        // KEV outranks raw CVE count/severity, same ordering priority as
        // the Vulnerabilities page's own fleet-wide sort.
        if (a.has_kev !== b.has_kev) return sign * (a.has_kev ? -1 : 1);
        return sign * (b.cve_count - a.cve_count);
      default:
        return 0;
    }
  });
}

// Compact risk indicator for the host list - reuses the same severity
// banding (cveSeverityClass) and KEV badge styling the Vulnerabilities
// page and host detail already use, just condensed to a single glance:
// a count, colored by the host's single worst CVE, plus a KEV marker if
// any of its CVEs are confirmed actively exploited. Renders nothing for
// a host with no known CVEs, same "absence isn't shown as a zero" as the
// rest of this app's badge-based indicators.
// Flags open ports this host's own latest scan didn't re-confirm. Not a
// severity signal - it means "this count may be overstated", which is
// worth seeing next to the count itself rather than only on Host Detail.
function StalePortBadge({ count }: { count: number }) {
  if (!count) return null;
  return (
    <span
      className="stale-badge"
      title={`${count} open port(s) were not re-confirmed by this host's most recent scan - masscan only reports ports it currently sees open, so these may already be closed`}
    >
      {count} unconfirmed
    </span>
  );
}

function RiskBadge({ host }: { host: HostSummary }) {
  if (host.cve_count === 0) return null;
  return (
    <span className="risk-badge-group" title={`${host.cve_count} known CVE(s) on this host's open ports`}>
      <span className={`cve-badge cve-${cveSeverityClass({ cvssScore: host.max_cvss_score })}`}>
        {host.cve_count} CVE{host.cve_count === 1 ? "" : "s"}
      </span>
      {host.has_kev && (
        <span className="kev-badge" title="At least one CVE on this host is on CISA's Known Exploited Vulnerabilities catalog">
          KEV
        </span>
      )}
    </span>
  );
}

export default function Dashboard({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const canEdit = me.role === "admin" || me.role === "operator";
  const isAdmin = me.role === "admin";
  const health = useFleetHealth(me);
  const navigate = useNavigate();
  // Filters live in the URL (not just component state) so that navigating
  // to a host and back restores them instead of resetting to defaults -
  // Dashboard fully remounts on that route change.
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = filtersFromSearchParams(searchParams);
  const page = Number(searchParams.get("page") ?? "1") || 1;
  const [queryInput, setQueryInput] = useState(filters.q ?? "");
  const pageSize = me.preferences.hostsPageSize ?? PAGE_SIZE;
  const [hostList, setHostList] = useState<HostListResult>({ items: [], total: 0, page: 1, pageSize });
  const [facets, setFacets] = useState<Facets | null>(null);
  // Separate from `facets.ports` (top 10 only) - fetched on demand only
  // when "show all ports" is clicked, since it's a strictly bigger,
  // rarely-needed payload most sessions never touch.
  const [allPorts, setAllPorts] = useState<Facets["ports"] | null>(null);
  const [showAllPorts, setShowAllPorts] = useState(false);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showRescanModal, setShowRescanModal] = useState(false);
  const [loading, setLoading] = useState(true);
  // View mode / column visibility / sort are display preferences, not
  // search filters, so they live in localStorage rather than the URL.
  const [tablePrefs, setTablePrefs] = useState<TablePrefs>(loadTablePrefs);
  // Bulk selection is ephemeral component state, not a filter or display
  // preference - reset whenever the underlying list changes (see the
  // searchParams effect below) so stale, no-longer-visible ids can't
  // silently stick around across a filter or page change.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkTagInput, setBulkTagInput] = useState("");
  const [bulkStatus, setBulkStatus] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [saveSearchName, setSaveSearchName] = useState("");
  const [activeScanJobs, setActiveScanJobs] = useState<ActiveScanJob[]>([]);
  const [detailsJobId, setDetailsJobId] = useState<string | null>(null);
  // Forces a re-render every few seconds so elapsedLabel's "running for
  // Xm Ys" stays live between polls, not just when the job list changes.
  const [, setClockTick] = useState(0);

  useEffect(() => {
    localStorage.setItem(TABLE_PREFS_KEY, JSON.stringify(tablePrefs));
  }, [tablePrefs]);

  useEffect(() => {
    loadSavedSearches();
  }, []);

  useEffect(() => {
    loadActiveScanJobs();
    const jobsInterval = setInterval(loadActiveScanJobs, 5000);
    const clockInterval = setInterval(() => setClockTick((t) => t + 1), 1000);
    return () => {
      clearInterval(jobsInterval);
      clearInterval(clockInterval);
    };
  }, []);

  async function loadActiveScanJobs() {
    try {
      setActiveScanJobs(await api.activeScanJobs());
    } catch {
      setActiveScanJobs([]);
    }
  }

  async function handleDismissScanJob(id: string) {
    if (!window.confirm("Dismiss this stale scan? The scanner isn't notified - if it's actually still running, its next update is simply ignored.")) {
      return;
    }
    await api.dismissScanJob(id);
    await loadActiveScanJobs();
  }

  async function handleCancelScanJob(id: string) {
    if (!window.confirm("Stop this scan? The scanner will notice on its next check and abort.")) {
      return;
    }
    await api.cancelScanJob(id);
    await loadActiveScanJobs();
  }

  async function loadSavedSearches() {
    try {
      setSavedSearches(await api.savedSearches());
    } catch {
      setSavedSearches([]);
    }
  }

  async function handleSaveSearch(e: FormEvent) {
    e.preventDefault();
    if (!saveSearchName.trim()) return;
    const params = new URLSearchParams(searchParams);
    params.delete("page");
    await api.createSavedSearch(saveSearchName.trim(), Object.fromEntries(params));
    setSaveSearchName("");
    await loadSavedSearches();
  }

  function applySavedSearch(search: SavedSearch) {
    setSearchParams(new URLSearchParams(search.filters));
  }

  async function handleDeleteSavedSearch(id: string) {
    await api.deleteSavedSearch(id);
    await loadSavedSearches();
  }

  function setSort(key: SortKey) {
    setTablePrefs((prev) =>
      prev.sortKey === key
        ? { ...prev, sortDirection: prev.sortDirection === "asc" ? "desc" : "asc" }
        : { ...prev, sortKey: key, sortDirection: "asc" }
    );
  }

  function toggleColumn(key: ColumnKey) {
    setTablePrefs((prev) => ({
      ...prev,
      columns: prev.columns.includes(key) ? prev.columns.filter((c) => c !== key) : [...prev.columns, key],
    }));
  }

  function sortIndicator(key: SortKey): string {
    if (tablePrefs.sortKey !== key) return "";
    return tablePrefs.sortDirection === "asc" ? " ▲" : " ▼";
  }

  useEffect(() => {
    api.agents().then(setAgents).catch(() => setAgents([]));
  }, []);

  // Seeds the Scanner filter from the account's own default (Account page)
  // on a genuinely fresh tab/session only - guarded by sessionStorage
  // (not just "the URL has no scannerAgentId yet") so that explicitly
  // clearing the filter back to "All Scanner" sticks for the rest of this
  // browsing session, instead of the default silently reapplying itself
  // every time Dashboard remounts (e.g. navigating back from a host page).
  useEffect(() => {
    const key = "porttorch.defaultScannerConsidered";
    if (sessionStorage.getItem(key)) return;
    sessionStorage.setItem(key, "1");
    if (!searchParams.has("scannerAgentId") && me.preferences.defaultScannerAgentId) {
      updateFilters({ scannerAgentIds: [me.preferences.defaultScannerAgentId] });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setQueryInput(filters.q ?? "");
    setSelected(new Set());
    setBulkStatus(null);
    load(filters, page);
    // Scoped server-side to these same filters (see api.ts's facets()) so
    // e.g. a keyword search live-updates the Ports/Services/... sidebar
    // counts down to matching hosts, not just the host list itself.
    api.facets(filters).then(setFacets).catch(() => setFacets(null));
    // The previously-fetched "all ports" list (if the user had expanded
    // it) was scoped to the old filters - drop it so the next expand
    // re-fetches against the current ones instead of showing stale counts.
    setAllPorts(null);
    setShowAllPorts(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams.toString()]);

  async function load(f: HostFilters, p: number) {
    setLoading(true);
    try {
      setHostList(await api.hosts(f, p, pageSize));
    } finally {
      setLoading(false);
    }
  }

  function toggleSelected(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAllOnPage() {
    const pageIds = hostList.items.map((h) => h.id);
    const allSelected = pageIds.length > 0 && pageIds.every((id) => selected.has(id));
    setSelected(allSelected ? new Set() : new Set(pageIds));
  }

  async function handleBulkTag(e: FormEvent) {
    e.preventDefault();
    const tag = bulkTagInput.trim();
    if (!tag || selected.size === 0) return;
    setBulkBusy(true);
    setBulkStatus(null);
    try {
      const results = await Promise.allSettled([...selected].map((id) => api.addHostTag(id, tag)));
      const failed = results.filter((r) => r.status === "rejected").length;
      setBulkStatus(
        failed === 0
          ? `Tagged ${selected.size} host(s) with "${tag}".`
          : `Tagged ${selected.size - failed} host(s), ${failed} failed.`
      );
      setBulkTagInput("");
      await Promise.all([load(filters, page), api.facets(filters).then(setFacets).catch(() => {})]);
    } finally {
      setBulkBusy(false);
    }
  }

  async function handleBulkRescan(profile: NSEProfileSelection, nucleiProfile: NucleiProfileSelection, priority: ScanPriority) {
    if (selected.size === 0) return;
    setShowRescanModal(false);
    setBulkBusy(true);
    setBulkStatus(null);
    try {
      const results = await Promise.allSettled([...selected].map((id) => api.rescan(id, profile, nucleiProfile, priority)));
      const failed = results.filter((r) => r.status === "rejected").length;
      setBulkStatus(
        failed === 0
          ? `Rescan requested for ${selected.size} host(s).`
          : `Rescan requested for ${selected.size - failed} host(s), ${failed} failed (e.g. no known ports yet).`
      );
    } finally {
      setBulkBusy(false);
    }
  }

  // Retiring in bulk is what a decommissioning actually looks like -
  // twenty machines go at once, and the alternative was twenty trips to
  // twenty host pages or deleting them, which throws the history away.
  // Operator-level like the single-host action it loops, unlike delete.
  async function handleBulkRetire(retired: boolean) {
    if (selected.size === 0) return;
    setBulkBusy(true);
    setBulkStatus(null);
    try {
      const results = await Promise.allSettled([...selected].map((id) => api.setHostRetired(id, retired)));
      const failed = results.filter((r) => r.status === "rejected").length;
      const verb = retired ? "Retired" : "Un-retired";
      setBulkStatus(
        failed === 0
          ? `${verb} ${selected.size} host(s).`
          : `${verb} ${selected.size - failed} host(s), ${failed} failed.`
      );
      setSelected(new Set());
      await load(filters, page);
    } finally {
      setBulkBusy(false);
    }
  }

  async function handleBulkDelete() {
    if (selected.size === 0) return;
    if (
      !window.confirm(
        `Permanently delete ${selected.size} selected host(s)? This removes their ports, screenshots, certificates, tags, and comments. This can't be undone.`
      )
    ) {
      return;
    }
    setBulkBusy(true);
    setBulkStatus(null);
    try {
      const results = await Promise.allSettled([...selected].map((id) => api.deleteHost(id)));
      const failed = results.filter((r) => r.status === "rejected").length;
      setBulkStatus(
        failed === 0
          ? `Deleted ${selected.size} host(s).`
          : `Deleted ${selected.size - failed} host(s), ${failed} failed.`
      );
      setSelected(new Set());
      await Promise.all([load(filters, page), api.facets(filters).then(setFacets).catch(() => {})]);
    } finally {
      setBulkBusy(false);
    }
  }

  // Changing an actual filter always resets to page 1 (built as a fresh
  // URLSearchParams, so "page" is dropped unless the patch sets it).
  // goToPage below preserves the current filters and only touches "page".
  function updateFilters(patch: Partial<HostFilters>) {
    const merged = { ...filters, ...patch };
    const next = new URLSearchParams();
    if (merged.q) next.set("q", merged.q);
    const withNegated = (include: (string | number)[] = [], exclude: (string | number)[] = []) =>
      [...include.map(String), ...exclude.map((v) => `-${v}`)].join(",");
    const portParam = withNegated(merged.ports, merged.excludePorts);
    const serviceParam = withNegated(merged.services, merged.excludeServices);
    const tagParam = withNegated(merged.tags, merged.excludeTags);
    if (portParam) next.set("port", portParam);
    if (serviceParam) next.set("service", serviceParam);
    if (tagParam) next.set("tag", tagParam);
    if (merged.osFamily) next.set("osFamily", merged.osFamily);
    if (merged.deviceType) next.set("deviceType", merged.deviceType);
    if (merged.hideEmpty) next.set("hideEmpty", "true");
    if (merged.hideRetired) next.set("hideRetired", "true");
    if (merged.hasScreenshot) next.set("hasScreenshot", "true");
    if (merged.hasStalePorts) next.set("hasStalePorts", "true");
    if (merged.lastSeenAfter) next.set("lastSeenAfter", merged.lastSeenAfter);
    if (merged.lastSeenBefore) next.set("lastSeenBefore", merged.lastSeenBefore);
    if (merged.scannerAgentIds?.length) next.set("scannerAgentId", merged.scannerAgentIds.join(","));
    setSearchParams(next);
  }

  function goToPage(nextPage: number) {
    const next = new URLSearchParams(searchParams);
    if (nextPage > 1) next.set("page", String(nextPage));
    else next.delete("page");
    setSearchParams(next);
  }

  function applyQuery() {
    updateFilters({ q: queryInput.trim() || undefined });
  }

  // Clicking a facet cycles through three states rather than two:
  // off -> include -> exclude -> off. There's no separate "negate" control
  // to discover, and the second click on an already-active facet is the
  // natural place for "actually, hide these" - the alternative (a modifier
  // key) is invisible to anyone who doesn't already know it's there.
  function cycleFacet<T>(
    include: T[] | undefined,
    exclude: T[] | undefined,
    value: T
  ): { include: T[] | undefined; exclude: T[] | undefined } {
    const inc = include ?? [];
    const exc = exclude ?? [];
    if (inc.includes(value)) {
      return { include: orUndefined(inc.filter((v) => v !== value)), exclude: orUndefined([...exc, value]) };
    }
    if (exc.includes(value)) {
      return { include: orUndefined(inc), exclude: orUndefined(exc.filter((v) => v !== value)) };
    }
    return { include: orUndefined([...inc, value]), exclude: orUndefined(exc) };
  }

  // Three visual states to match the three click states. The title is
  // what makes the cycle discoverable at all - without it, a second click
  // turning a filter into its opposite would just look like a bug.
  function facetClass(included: boolean, excluded: boolean): string {
    return `facet-item ${included ? "active" : ""} ${excluded ? "excluded" : ""}`.trim();
  }

  function facetTitle(included: boolean, excluded: boolean): string {
    if (included) return "Showing only hosts with this - click to exclude them instead";
    if (excluded) return "Hiding hosts with this - click to clear";
    return "Click to show only hosts with this";
  }

  function togglePortFacet(port: number) {
    const next = cycleFacet(filters.ports, filters.excludePorts, port);
    updateFilters({ ports: next.include, excludePorts: next.exclude });
  }

  // Removing a chip clears that value outright - deliberately not the
  // toggle above, which would advance an included filter to *excluded*
  // and leave the chip apparently un-removable.
  function clearPortFacet(port: number) {
    updateFilters({
      ports: orUndefined((filters.ports ?? []).filter((p) => p !== port)),
      excludePorts: orUndefined((filters.excludePorts ?? []).filter((p) => p !== port)),
    });
  }

  function clearServiceFacet(service: string) {
    updateFilters({
      services: orUndefined((filters.services ?? []).filter((v) => v !== service)),
      excludeServices: orUndefined((filters.excludeServices ?? []).filter((v) => v !== service)),
    });
  }

  function clearTagFacet(tag: string) {
    updateFilters({
      tags: orUndefined((filters.tags ?? []).filter((v) => v !== tag)),
      excludeTags: orUndefined((filters.excludeTags ?? []).filter((v) => v !== tag)),
    });
  }

  async function handleShowAllPorts() {
    if (!allPorts) {
      setAllPorts(await api.allPortFacets(filters));
    }
    setShowAllPorts(true);
  }

  function toggleServiceFacet(service: string) {
    const next = cycleFacet(filters.services, filters.excludeServices, service);
    updateFilters({ services: next.include, excludeServices: next.exclude });
  }

  function toggleTagFacet(tag: string) {
    const next = cycleFacet(filters.tags, filters.excludeTags, tag);
    updateFilters({ tags: next.include, excludeTags: next.exclude });
  }


  function toggleOsFamilyFacet(osFamily: string) {
    updateFilters({ osFamily: filters.osFamily === osFamily ? undefined : osFamily });
  }

  function toggleDeviceTypeFacet(deviceType: string) {
    updateFilters({ deviceType: filters.deviceType === deviceType ? undefined : deviceType });
  }

  // Same add/remove-from-array pattern as togglePortFacet/toggleServiceFacet
  // above, used by a host card/row's own "via <scanner>" text - lets a
  // user filter by clicking what they see in the list itself, not just
  // the sidebar facets or the ScannerMultiSelect dropdown.
  function toggleScannerAgentFilter(scannerAgentId: string) {
    const current = filters.scannerAgentIds ?? [];
    const next = current.includes(scannerAgentId)
      ? current.filter((id) => id !== scannerAgentId)
      : [...current, scannerAgentId];
    updateFilters({ scannerAgentIds: next.length ? next : undefined });
  }

  const activeChips: Array<{ key: string; label: string; onRemove: () => void }> = [];
  if (filters.q) {
    activeChips.push({
      key: "q",
      label: `Search: ${filters.q}`,
      onRemove: () => {
        setQueryInput("");
        updateFilters({ q: undefined });
      },
    });
  }
  for (const port of filters.ports ?? []) {
    activeChips.push({
      key: `port-${port}`,
      label: `Port: ${port}`,
      onRemove: () => clearPortFacet(port),
    });
  }
  for (const service of filters.services ?? []) {
    activeChips.push({
      key: `service-${service}`,
      label: `Service: ${service}`,
      onRemove: () => clearServiceFacet(service),
    });
  }
  for (const tag of filters.tags ?? []) {
    activeChips.push({
      key: `tag-${tag}`,
      label: `Tag: ${tag}`,
      onRemove: () => clearTagFacet(tag),
    });
  }
  // Exclusions get their own chips, labelled so the direction is
  // unmistakable - an unlabelled "Port: 53" chip that meant the opposite
  // of the one above it would be worse than no chip at all.
  for (const port of filters.excludePorts ?? []) {
    activeChips.push({
      key: `exclude-port-${port}`,
      label: `Not port: ${port}`,
      onRemove: () => clearPortFacet(port),
    });
  }
  for (const service of filters.excludeServices ?? []) {
    activeChips.push({
      key: `exclude-service-${service}`,
      label: `Not service: ${service}`,
      onRemove: () => clearServiceFacet(service),
    });
  }
  for (const tag of filters.excludeTags ?? []) {
    activeChips.push({
      key: `exclude-tag-${tag}`,
      label: `Not tag: ${tag}`,
      onRemove: () => clearTagFacet(tag),
    });
  }
  if (filters.osFamily) {
    activeChips.push({
      key: "osFamily",
      label: `OS: ${filters.osFamily}`,
      onRemove: () => updateFilters({ osFamily: undefined }),
    });
  }
  if (filters.deviceType) {
    activeChips.push({
      key: "deviceType",
      label: `Device: ${filters.deviceType}`,
      onRemove: () => updateFilters({ deviceType: undefined }),
    });
  }
  if (filters.lastSeenAfter) {
    activeChips.push({
      key: "lastSeenAfter",
      label: `Last seen from: ${filters.lastSeenAfter}`,
      onRemove: () => updateFilters({ lastSeenAfter: undefined }),
    });
  }
  if (filters.lastSeenBefore) {
    activeChips.push({
      key: "lastSeenBefore",
      label: `Last seen until: ${filters.lastSeenBefore}`,
      onRemove: () => updateFilters({ lastSeenBefore: undefined }),
    });
  }
  for (const scannerAgentId of filters.scannerAgentIds ?? []) {
    const agentName = agents.find((a) => a.id === scannerAgentId)?.name ?? scannerAgentId;
    activeChips.push({
      key: `scannerAgentId-${scannerAgentId}`,
      label: `Scanner: ${agentName}`,
      onRemove: () =>
        updateFilters({
          scannerAgentIds: filters.scannerAgentIds?.filter((id) => id !== scannerAgentId),
        }),
    });
  }

  // Passed to the host detail page via router state so its prev/next
  // buttons can step through the same (filtered/sorted) list that's
  // currently on screen - matches whichever order is actually visible,
  // since the table view can be sorted independently of the grid's
  // server-provided order. filters/page/pageSize/total ride along too, so
  // running off either end of this page lets HostDetail fetch the
  // adjacent page instead of just stopping there.
  const navHostIds =
    tablePrefs.view === "table"
      ? sortHosts(hostList.items, tablePrefs.sortKey, tablePrefs.sortDirection).map((h) => h.id)
      : hostList.items.map((h) => h.id);
  const navState = { hostIds: navHostIds, filters, page, pageSize, total: hostList.total };

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      {!health.loading && !health.error && health.overall !== "ok" && (
        <Link
          to="/health"
          className={`callout-link ${health.overall === "critical" ? "callout-danger" : "callout-warning"}`}
        >
          <IconWarning /> Fleet health needs attention ({STATUS_LABEL[health.overall]}) - view details
        </Link>
      )}

      {me.preferences.showActiveScansBanner && activeScanJobs.length > 0 && (
        <div className="active-scans">
          <h2>Active scans ({activeScanJobs.length})</h2>
          <ul className="active-scans-list">
            {activeScanJobs.map((j) => (
              <li key={j.id}>
                <span className="active-scan-target">
                  {j.target_spec} <span className="host-meta">(ports {j.port_spec})</span>
                </span>
                <span className="host-meta">
                  {j.scanner_agent_name ?? "unknown scanner"} · running {elapsedLabel(j.started_at)}
                </span>
                {j.is_stale && (
                  <span className="stale-badge" title="No update in a while - the scanner may be offline or have died mid-scan">
                    stale
                  </span>
                )}
                <button className="btn-icon-label" onClick={() => setDetailsJobId(j.id)}>
                  <IconInfo /> Details
                </button>
                {j.is_stale && canEdit && (
                  <button className="btn-icon-label" onClick={() => handleDismissScanJob(j.id)}>
                    <IconX /> Dismiss
                  </button>
                )}
                {j.cancellable && canEdit && (
                  <button className="btn-icon-label" onClick={() => handleCancelScanJob(j.id)} disabled={j.cancel_requested}>
                    <IconStop /> {j.cancel_requested ? "Stopping..." : "Stop"}
                  </button>
                )}
                {j.applicable_excludes && j.applicable_excludes.length > 0 && (
                  <div className="host-meta active-scan-excludes">
                    Excludes: {j.applicable_excludes.map((e) => `${e.kind}: ${e.value}`).join(", ")}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <form
        className="search-bar"
        onSubmit={(e) => {
          e.preventDefault();
          applyQuery();
        }}
      >
        <input
          placeholder="Search by IP, CIDR range, hostname, service, banner, CVE..."
          value={queryInput}
          onChange={(e) => setQueryInput(e.target.value)}
        />
        <button type="submit" className="btn-icon-label">
          <IconSearch /> Search
        </button>
      </form>

      <div className="list-controls">
        <div className="list-controls-filters">
          <label className="date-range-filter">
            Scanner
            <ScannerMultiSelect
              agents={agents}
              selectedIds={filters.scannerAgentIds ?? []}
              onChange={(ids) => updateFilters({ scannerAgentIds: ids.length ? ids : undefined })}
            />
          </label>
          <label className="hide-empty-toggle">
            <input
              type="checkbox"
              checked={filters.hideEmpty ?? false}
              onChange={(e) => updateFilters({ hideEmpty: e.target.checked || undefined })}
            />
            Hide hosts without open ports
          </label>
          <label className="hide-empty-toggle">
            <input
              type="checkbox"
              checked={filters.hideRetired ?? false}
              onChange={(e) => updateFilters({ hideRetired: e.target.checked || undefined })}
            />
            Hide retired hosts
          </label>
          <label className="hide-empty-toggle">
            <input
              type="checkbox"
              checked={filters.hasScreenshot ?? false}
              onChange={(e) => updateFilters({ hasScreenshot: e.target.checked || undefined })}
            />
            Only hosts with a screenshot
          </label>
          <label
            className="hide-empty-toggle"
            title="Ports still listed as open that this host's own latest scan didn't re-confirm. masscan only reports ports it currently sees open, so one that quietly stops answering keeps its last known state - these may already be closed."
          >
            <input
              type="checkbox"
              checked={filters.hasStalePorts ?? false}
              onChange={(e) => updateFilters({ hasStalePorts: e.target.checked || undefined })}
            />
            Only hosts with unconfirmed ports
          </label>
          <div className="last-seen-range">
            <label className="date-range-filter">
              Last seen from
              <input
                type="date"
                value={filters.lastSeenAfter ?? ""}
                onChange={(e) => updateFilters({ lastSeenAfter: e.target.value || undefined })}
              />
            </label>
            <label className="date-range-filter">
              until
              <input
                type="date"
                value={filters.lastSeenBefore ?? ""}
                onChange={(e) => updateFilters({ lastSeenBefore: e.target.value || undefined })}
              />
            </label>
          </div>
        </div>
      </div>

      <div className="saved-searches">
        {savedSearches.map((s) => (
          <span key={s.id} className="chip saved-search-chip">
            <button className="saved-search-apply" onClick={() => applySavedSearch(s)}>
              {s.name}
            </button>
            {canEdit && (
              <button className="saved-search-remove" onClick={() => handleDeleteSavedSearch(s.id)} title="Delete saved search">
                &times;
              </button>
            )}
          </span>
        ))}
        {canEdit && (
          <form className="save-search-form" onSubmit={handleSaveSearch}>
            <input
              placeholder="Save current search as..."
              value={saveSearchName}
              onChange={(e) => setSaveSearchName(e.target.value)}
            />
            <button type="submit" className="btn-icon-label" disabled={!saveSearchName.trim()}>
              <IconBookmark /> Save search
            </button>
          </form>
        )}
        <div className="csv-export-controls">
          <button type="button" className="btn-icon-label" onClick={() => setShowExportModal(true)}>
            <IconDownload /> Export data
          </button>
        </div>
      </div>

      {showExportModal && (
        <ExportModal filters={filters} selectedIds={[...selected]} onClose={() => setShowExportModal(false)} />
      )}

      {showRescanModal && (
        <RescanModal hostCount={selected.size} onConfirm={handleBulkRescan} onClose={() => setShowRescanModal(false)} />
      )}

      {activeChips.length > 0 && (
        <div className="filter-chips">
          {activeChips.map((chip) => (
            <button key={chip.key} className="chip" onClick={chip.onRemove}>
              {chip.label} &times;
            </button>
          ))}
        </div>
      )}

      {canEdit && selected.size > 0 && (
        <div className="bulk-actions">
          <span className="host-meta">{selected.size} selected</span>
          <form className="bulk-tag-form" onSubmit={handleBulkTag}>
            <input placeholder="Add tag to selected..." value={bulkTagInput} onChange={(e) => setBulkTagInput(e.target.value)} />
            <button type="submit" className="btn-icon-label" disabled={bulkBusy || !bulkTagInput.trim()}>
              <IconPlus /> Add tag
            </button>
          </form>
          <button className="btn-icon-label" onClick={() => setShowRescanModal(true)} disabled={bulkBusy}>
            <IconRefresh /> Rescan selected
          </button>
          <button
            className="btn-icon-label"
            onClick={() => handleBulkRetire(true)}
            disabled={bulkBusy}
            title="Stop host.disappeared alerts for these hosts. Nothing else changes - they stay in the list with all their history, and a port opening on one is still reported."
          >
            <IconArchive /> Retire selected
          </button>
          <button className="btn-icon-label" onClick={() => handleBulkRetire(false)} disabled={bulkBusy}>
            <IconArchive /> Un-retire
          </button>
          {isAdmin && (
            <button className="btn-icon-label" onClick={handleBulkDelete} disabled={bulkBusy}>
              <IconTrash /> Delete selected
            </button>
          )}
          <button className="link-button btn-icon-label" onClick={() => setSelected(new Set())}>
            <IconX /> Clear selection
          </button>
        </div>
      )}
      {bulkStatus && <p className="host-meta">{bulkStatus}</p>}

      <div className="dashboard-layout">
        <aside className="facets">
          <h2>Ports</h2>
          {facets && facets.ports.length > 0 ? (
            <>
              <ul className={`facet-list ${showAllPorts ? "facet-list-scrollable" : ""}`}>
                {(showAllPorts && allPorts ? allPorts : facets.ports).map((p) => (
                  <li key={p.port}>
                    <button
                      className={facetClass(filters.ports?.includes(p.port) ?? false, filters.excludePorts?.includes(p.port) ?? false)}
                      title={facetTitle(filters.ports?.includes(p.port) ?? false, filters.excludePorts?.includes(p.port) ?? false)}
                      onClick={() => togglePortFacet(p.port)}
                    >
                      <span>{p.port}</span>
                      <span className="facet-count">{p.count}</span>
                    </button>
                  </li>
                ))}
              </ul>
              <button
                className="link-button"
                onClick={() => (showAllPorts ? setShowAllPorts(false) : handleShowAllPorts())}
              >
                {showAllPorts ? "show top 10" : "show all ports"}
              </button>
            </>
          ) : (
            <p className="empty">No data</p>
          )}

          <h2>Services</h2>
          {facets && facets.services.length > 0 ? (
            <ul className="facet-list">
              {facets.services.map((s) => (
                <li key={s.service}>
                  <button
                    className={facetClass(filters.services?.includes(s.service) ?? false, filters.excludeServices?.includes(s.service) ?? false)}
                    title={facetTitle(filters.services?.includes(s.service) ?? false, filters.excludeServices?.includes(s.service) ?? false)}
                    onClick={() => toggleServiceFacet(s.service)}
                  >
                    <span>{s.service}</span>
                    <span className="facet-count">{s.count}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No data</p>
          )}

          <h2>Tags</h2>
          {facets && facets.tags.length > 0 ? (
            <ul className="facet-list">
              {facets.tags.map((t) => (
                <li key={t.tag}>
                  <button
                    className={facetClass(filters.tags?.includes(t.tag) ?? false, filters.excludeTags?.includes(t.tag) ?? false)}
                    title={facetTitle(filters.tags?.includes(t.tag) ?? false, filters.excludeTags?.includes(t.tag) ?? false)}
                    onClick={() => toggleTagFacet(t.tag)}
                  >
                    <span>{t.tag}</span>
                    <span className="facet-count">{t.count}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No data</p>
          )}

          <h2>OS Family</h2>
          {facets && facets.osFamilies.length > 0 ? (
            <ul className="facet-list">
              {facets.osFamilies.map((o) => (
                <li key={o.osFamily}>
                  <button
                    className={`facet-item ${filters.osFamily === o.osFamily ? "active" : ""}`}
                    onClick={() => toggleOsFamilyFacet(o.osFamily)}
                  >
                    <span>{o.osFamily}</span>
                    <span className="facet-count">{o.count}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No data</p>
          )}

          <h2>Device Type</h2>
          {facets && facets.deviceTypes.length > 0 ? (
            <ul className="facet-list">
              {facets.deviceTypes.map((d) => (
                <li key={d.deviceType}>
                  <button
                    className={`facet-item ${filters.deviceType === d.deviceType ? "active" : ""}`}
                    onClick={() => toggleDeviceTypeFacet(d.deviceType)}
                  >
                    <span>{d.deviceType}</span>
                    <span className="facet-count">{d.count}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No data</p>
          )}
        </aside>

        <main>
          <div className="view-controls">
            {tablePrefs.view === "table" && (
              <div className="column-toggles">
                Columns:
                {TOGGLEABLE_COLUMNS.map((c) => (
                  <label key={c.key}>
                    <input
                      type="checkbox"
                      checked={tablePrefs.columns.includes(c.key)}
                      onChange={() => toggleColumn(c.key)}
                    />
                    {c.label}
                  </label>
                ))}
              </div>
            )}
            <div className="view-toggle">
              <button
                className={tablePrefs.view === "grid" ? "active" : ""}
                onClick={() => setTablePrefs((prev) => ({ ...prev, view: "grid" }))}
              >
                Grid
              </button>
              <button
                className={tablePrefs.view === "table" ? "active" : ""}
                onClick={() => setTablePrefs((prev) => ({ ...prev, view: "table" }))}
              >
                Table
              </button>
            </div>
          </div>

          {loading ? (
            <p>Loading...</p>
          ) : hostList.items.length === 0 ? (
            <p className="empty">No hosts found. Maybe no scan results have been submitted yet?</p>
          ) : tablePrefs.view === "table" ? (
            <div className="table-scroll">
              <table className="host-table">
                <thead>
                  <tr>
                    {canEdit && (
                      <th className="select-col">
                        <input
                          type="checkbox"
                          checked={hostList.items.length > 0 && hostList.items.every((h) => selected.has(h.id))}
                          onChange={toggleSelectAllOnPage}
                          onClick={(e) => e.stopPropagation()}
                        />
                      </th>
                    )}
                    <th onClick={() => setSort("ip")}>IP{sortIndicator("ip")}</th>
                    {tablePrefs.columns.includes("hostname") && (
                      <th onClick={() => setSort("hostname")}>Hostname{sortIndicator("hostname")}</th>
                    )}
                    {tablePrefs.columns.includes("open_port_count") && (
                      <th onClick={() => setSort("open_port_count")}>Open Ports{sortIndicator("open_port_count")}</th>
                    )}
                    {tablePrefs.columns.includes("last_seen_at") && (
                      <th onClick={() => setSort("last_seen_at")}>Last Seen{sortIndicator("last_seen_at")}</th>
                    )}
                    {tablePrefs.columns.includes("screenshot") && (
                      <th onClick={() => setSort("screenshot")}>Screenshot{sortIndicator("screenshot")}</th>
                    )}
                    {tablePrefs.columns.includes("device") && (
                      <th onClick={() => setSort("device")}>OS/Device{sortIndicator("device")}</th>
                    )}
                    {tablePrefs.columns.includes("mac") && (
                      <th onClick={() => setSort("mac")}>MAC{sortIndicator("mac")}</th>
                    )}
                    {tablePrefs.columns.includes("scanner") && (
                      <th onClick={() => setSort("scanner")}>Scanner{sortIndicator("scanner")}</th>
                    )}
                    {tablePrefs.columns.includes("risk") && (
                      <th onClick={() => setSort("risk")}>Risk{sortIndicator("risk")}</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {sortHosts(hostList.items, tablePrefs.sortKey, tablePrefs.sortDirection).map((h) => (
                    <tr key={h.id} onClick={() => navigate(`/hosts/${h.id}`, { state: navState })}>
                      {canEdit && (
                        <td className="select-col" onClick={(e) => e.stopPropagation()}>
                          <input type="checkbox" checked={selected.has(h.id)} onChange={() => toggleSelected(h.id)} />
                        </td>
                      )}
                      <td>
                        {h.ip}
                        {h.retired_at && <span className="chip-inline">retired</span>}
                      </td>
                      {tablePrefs.columns.includes("hostname") && <td>{h.hostname ?? "-"}</td>}
                      {tablePrefs.columns.includes("open_port_count") && (
                        <td>
                          {h.open_port_count}
                          <StalePortBadge count={h.stale_port_count} />
                        </td>
                      )}
                      {tablePrefs.columns.includes("last_seen_at") && (
                        <td>{formatDateTime(h.last_seen_at, me.preferences)}</td>
                      )}
                      {tablePrefs.columns.includes("screenshot") && <td>{h.thumbnail_kind ?? "-"}</td>}
                      {tablePrefs.columns.includes("device") && (
                        <td onClick={(e) => e.stopPropagation()}>
                          {h.device_type || h.os_family ? (
                            <>
                              {h.device_type && (
                                <button
                                  type="button"
                                  className="link-button"
                                  title={`Filter by device type: ${h.device_type}`}
                                  onClick={() => toggleDeviceTypeFacet(h.device_type!)}
                                >
                                  {h.device_type}
                                </button>
                              )}
                              {h.device_type && h.os_family && " · "}
                              {h.os_family && (
                                <button
                                  type="button"
                                  className="link-button"
                                  title={`Filter by OS family: ${h.os_family}`}
                                  onClick={() => toggleOsFamilyFacet(h.os_family!)}
                                >
                                  {h.os_family}
                                </button>
                              )}
                            </>
                          ) : (
                            "-"
                          )}
                        </td>
                      )}
                      {tablePrefs.columns.includes("mac") && (
                        <td title={h.mac_vendor ?? undefined}>{h.mac_address ?? "-"}</td>
                      )}
                      {tablePrefs.columns.includes("scanner") && (
                        <td onClick={(e) => e.stopPropagation()}>
                          {h.scanner_agent_name && h.scanner_agent_id ? (
                            <button
                              type="button"
                              className="link-button"
                              title={`Filter by scanner: ${h.scanner_agent_name}`}
                              onClick={() => toggleScannerAgentFilter(h.scanner_agent_id!)}
                            >
                              {h.scanner_agent_name}
                            </button>
                          ) : (
                            "-"
                          )}
                        </td>
                      )}
                      {tablePrefs.columns.includes("risk") && <td><RiskBadge host={h} /></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="host-grid">
              {hostList.items.map((h) => (
                <Link key={h.id} to={`/hosts/${h.id}`} state={navState} className="host-card">
                  {canEdit && (
                    <input
                      type="checkbox"
                      className="host-card-select"
                      checked={selected.has(h.id)}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => toggleSelected(h.id)}
                    />
                  )}
                  {h.thumbnail_id ? (
                    <img
                      className="host-thumb"
                      src={`/api/${h.thumbnail_kind === "rdp" ? "rdp-screenshots" : "screenshots"}/${h.thumbnail_id}/image`}
                      alt=""
                      loading="lazy"
                    />
                  ) : (
                    <div className="host-thumb host-thumb-placeholder">no screenshot</div>
                  )}
                  <div className="host-ip">
                    {h.ip}
                    {h.retired_at && <span className="chip-inline">retired</span>}
                  </div>
                  {h.hostname && <div className="host-hostname">{h.hostname}</div>}
                  {h.scanner_agent_name && h.scanner_agent_id && (
                    <div className="host-meta">
                      via{" "}
                      <button
                        type="button"
                        className="link-button"
                        title={`Filter by scanner: ${h.scanner_agent_name}`}
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          toggleScannerAgentFilter(h.scanner_agent_id!);
                        }}
                      >
                        {h.scanner_agent_name}
                      </button>
                    </div>
                  )}
                  {(h.device_type || h.os_family) && (
                    <div className="tech-badges">
                      {h.device_type && (
                        <button
                          type="button"
                          className="tech-badge tech-badge-clickable"
                          title={`Filter by device type: ${h.device_type}`}
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            toggleDeviceTypeFacet(h.device_type!);
                          }}
                        >
                          {h.device_type}
                        </button>
                      )}
                      {h.os_family && (
                        <button
                          type="button"
                          className="tech-badge tech-badge-clickable"
                          title={`Filter by OS family: ${h.os_family}`}
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            toggleOsFamilyFacet(h.os_family!);
                          }}
                        >
                          {h.os_family}
                        </button>
                      )}
                    </div>
                  )}
                  {h.cve_count > 0 && (
                    <div className="cve-badges">
                      <RiskBadge host={h} />
                    </div>
                  )}
                  <div className="host-meta">
                    {h.open_port_count} open port(s)
                    <StalePortBadge count={h.stale_port_count} /> · last seen{" "}
                    {formatDateTime(h.last_seen_at, me.preferences)}
                  </div>
                </Link>
              ))}
            </div>
          )}

          {!loading && hostList.total > hostList.pageSize && (
            <div className="pagination">
              <button disabled={page <= 1} onClick={() => goToPage(page - 1)}>
                &larr; Prev
              </button>
              <span className="host-meta">
                Showing {(page - 1) * hostList.pageSize + 1}
                &ndash;{Math.min(page * hostList.pageSize, hostList.total)} of {hostList.total}
              </span>
              <button disabled={page * hostList.pageSize >= hostList.total} onClick={() => goToPage(page + 1)}>
                Next &rarr;
              </button>
            </div>
          )}
        </main>
      </div>

      {detailsJobId && <ScanProgressModal jobId={detailsJobId} onClose={() => setDetailsJobId(null)} />}
    </div>
  );
}
