// Filtering and paging for the screenshot gallery. Pure, so the rules -
// what a keyword matches, what counts as excluded - are testable without a
// database (gallery.test.ts).

export const DEFAULT_PAGE_SIZE = 48;
export const MAX_PAGE_SIZE = 200;
const MAX_KEYWORDS = 50;

export type GalleryKind = "all" | "web" | "rdp" | "changed";

export interface GalleryParams {
  page: number;
  pageSize: number;
  q: string;
  kind: GalleryKind;
  // Hide tiles matching any of these.
  exclude: string[];
  // Show only tiles whose host carries any of these tags.
  tags: string[];
  // Hide tiles whose host carries any of these tags.
  excludeTags: string[];
}

export interface GalleryTile {
  id: string;
  host_id: string;
  kind: "web" | "rdp";
  captured_at: Date | string;
  changed: boolean;
  searchText: string;
  // Every name the host goes by - DNS, what it calls itself, the name in
  // the captured URL - for hostname patterns. Not sent to the browser.
  hostNames?: string[];
  [key: string]: unknown;
}

function list(value: unknown, max: number): string[] {
  const raw = Array.isArray(value) ? value.join(",") : typeof value === "string" ? value : "";
  return [...new Set(raw.split(/[,\n]/).map((v) => v.trim()).filter(Boolean))].slice(0, max).map((v) => v.slice(0, 100));
}

export function parseGalleryParams(query: Record<string, unknown>): GalleryParams {
  const page = Math.max(1, parseInt(String(query.page ?? "1"), 10) || 1);
  const size = parseInt(String(query.pageSize ?? DEFAULT_PAGE_SIZE), 10) || DEFAULT_PAGE_SIZE;
  const kind = ["all", "web", "rdp", "changed"].includes(String(query.kind)) ? (String(query.kind) as GalleryKind) : "all";
  return {
    page,
    pageSize: Math.min(MAX_PAGE_SIZE, Math.max(1, size)),
    q: typeof query.q === "string" ? query.q.trim().slice(0, 200) : "",
    kind,
    exclude: list(query.exclude, MAX_KEYWORDS),
    tags: list(query.tags, MAX_KEYWORDS),
    excludeTags: list(query.excludeTags, MAX_KEYWORDS),
  };
}

// Lower-case and only letters and digits, on both sides of a comparison:
// "ipphone" then matches "IP Phone", "IP-Phone" and "ipphone", which is how
// people type a device class into a filter box without knowing how each
// vendor spells it.
export function normalise(text: string): string {
  return text.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "");
}

export function matchesKeyword(haystack: string, keyword: string): boolean {
  const k = normalise(keyword);
  return k.length > 0 && haystack.includes(k);
}

// An exclusion containing * or ? is a hostname pattern rather than a
// keyword: "prefix*name.domain.tld". Matched against the whole name - a
// pattern names hosts, so "web*" must not hide "intranet-web01" the way the
// keyword "web" would - case-insensitively, * for any run of characters
// (dots included), ? for exactly one.
export function isHostnamePattern(entry: string): boolean {
  return /[*?]/.test(entry);
}

export function hostnamePattern(entry: string): RegExp {
  const body = entry
    .trim()
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${body}$`);
}

export function filterGallery(tiles: GalleryTile[], tagsByHost: Map<string, string[]>, p: GalleryParams) {
  const lower = (xs: string[]) => xs.map((x) => x.toLowerCase());
  const includeTags = new Set(lower(p.tags));
  const patterns = p.exclude.filter(isHostnamePattern).map(hostnamePattern);
  const keywords = p.exclude.filter((e) => !isHostnamePattern(e));
  const excludeTags = new Set(lower(p.excludeTags));

  // Tags present on any tile, for the picker - counted before filtering so
  // a tag the current filter hides can still be chosen.
  const tagCounts = new Map<string, number>();
  for (const t of tiles) for (const tag of tagsByHost.get(t.host_id) ?? []) tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);

  let excluded = 0;
  const kept = tiles.filter((t) => {
    const tags = tagsByHost.get(t.host_id) ?? [];
    const hostTags = new Set(lower(tags));
    // Tags join the searchable text, so "managed" in the search box finds
    // hosts tagged so as well.
    const haystack = normalise(`${t.searchText} ${tags.join(" ")}`);
    if (includeTags.size > 0 && ![...includeTags].some((x) => hostTags.has(x))) return false;
    const names = (t.hostNames ?? []).map((n) => n.toLowerCase());
    const hidden =
      [...excludeTags].some((x) => hostTags.has(x)) ||
      keywords.some((keyword) => matchesKeyword(haystack, keyword)) ||
      patterns.some((re) => names.some((n) => re.test(n)));
    if (hidden) {
      excluded++;
      return false;
    }
    if (p.q && !matchesKeyword(haystack, p.q)) return false;
    return true;
  });

  // The chip counts describe what the other filters left, so a chip never
  // promises tiles the page then does not show.
  const counts = {
    all: kept.length,
    web: kept.filter((t) => t.kind === "web").length,
    rdp: kept.filter((t) => t.kind === "rdp").length,
    changed: kept.filter((t) => t.changed).length,
  };
  const ofKind = p.kind === "all" ? kept : p.kind === "changed" ? kept.filter((t) => t.changed) : kept.filter((t) => t.kind === p.kind);
  // Newest first: the point of the page is a quick look at what is out
  // there now, so anything just discovered belongs at the top.
  ofKind.sort((a, b) => new Date(b.captured_at).getTime() - new Date(a.captured_at).getTime());

  const pages = Math.max(1, Math.ceil(ofKind.length / p.pageSize));
  const page = Math.min(p.page, pages);
  const items = ofKind
    .slice((page - 1) * p.pageSize, page * p.pageSize)
    .map(({ searchText: _drop, hostNames: _names, ...rest }) => ({ ...rest, tags: tagsByHost.get(rest.host_id) ?? [] }));

  return {
    items,
    total: ofKind.length,
    page,
    pageSize: p.pageSize,
    counts,
    excluded,
    tags: [...tagCounts].map(([tag, count]) => ({ tag, count })).sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag)),
  };
}
