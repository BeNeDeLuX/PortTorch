import type { NavItem } from "./navigation";

// The quick search is mounted once, in App, while the button that opens
// it lives in every page's header. A window event connects the two
// without threading a callback through thirty pages.
export const QUICK_SEARCH_EVENT = "porttorch:quicksearch";

export function openQuickSearch() {
  window.dispatchEvent(new Event(QUICK_SEARCH_EVENT));
}

export function isMacPlatform(): boolean {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
}

export function quickSearchShortcut(): string {
  return isMacPlatform() ? "⌘K" : "Ctrl K";
}

// Ctrl+K everywhere, and Cmd+K on a Mac, where that is the convention.
// Deliberately not a bare "/" as some sites use: this app is full of text
// fields, and a single-key shortcut fires while someone is typing a CIDR.
export function isQuickSearchShortcut(e: Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey">): boolean {
  return e.key.toLowerCase() === "k" && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey;
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

export function looksLikeCve(query: string): boolean {
  return CVE_ID.test(query.trim());
}

// A partly typed IPv4 address - "10.20.41", "172.16." - read as the block
// it names, because that is what someone typing one is looking for. The
// host search matches a full address or a CIDR but deliberately not a
// text prefix of one (the same free-text field also matches banners and
// versions, where "10.2" is as likely to be a version as a network), so
// the quick search asks it for the CIDR instead of changing what that
// shared search - which saved searches and the External API also use -
// means. Whole octets only: one to three of them, each 0-255, with at
// least one dot, so a bare "22" stays a free-text search for a port or a
// version. A complete four-octet address is left alone; it already
// matches exactly.
export function ipv4PrefixToCidr(query: string): string | null {
  const m = /^(\d{1,3})\.(?:(\d{1,3})\.?)?(?:(\d{1,3})\.?)?$/.exec(query.trim());
  if (!m) return null;
  const octets = [m[1], m[2], m[3]].filter((o): o is string => o !== undefined).map(Number);
  if (octets.some((o) => o > 255)) return null;
  const padded = [...octets, 0, 0, 0].slice(0, 4);
  return `${padded.join(".")}/${octets.length * 8}`;
}

// How well a page matches, 0 for not at all. Every word typed has to
// appear somewhere in the label or the keywords, so "scan hist" finds
// Scan History and "cve" finds Vulnerabilities, while a label match ranks
// above a keyword-only one and a prefix above the middle of a word.
export function scorePage(page: Pick<NavItem, "label" | "keywords">, query: string): number {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return 0;
  const label = page.label.toLowerCase();
  const keywords = (page.keywords ?? "").toLowerCase();
  let score = 0;
  for (const w of words) {
    if (label.startsWith(w) || label.includes(` ${w}`)) score += 3;
    else if (label.includes(w)) score += 2;
    else if (keywords.includes(w)) score += 1;
    else return 0;
  }
  return score;
}

export function matchPages<T extends Pick<NavItem, "label" | "keywords">>(pages: T[], query: string, limit = 6): T[] {
  return pages
    .map((page) => ({ page, score: scorePage(page, query) }))
    .filter((m) => m.score > 0)
    .sort((a, b) => b.score - a.score || a.page.label.localeCompare(b.page.label))
    .slice(0, limit)
    .map((m) => m.page);
}
