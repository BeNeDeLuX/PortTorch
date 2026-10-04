import { intToIPv4, parseTargetSpecRanges, type IPv4Range } from "./ipRange";
import { MAX_TARGET_SPEC_LENGTH } from "./targetSpec";

// Address patterns - "every .125 in 10.46.0.0/16", "this /16 except .2
// and .4 in each /24" - written once and expanded here into the plain
// target grammar masscan already understands. Used in two places that
// must agree on what a pattern means: a scan's target (expandTargetPattern,
// at queue time) and a pattern exclude (expandExcludePattern, whenever a
// scanner fetches its excludes). Neither the scanner nor masscan ever sees
// a pattern; they receive the expanded list, so no scanner needs updating.
//
// The grammar, deliberately small:
//
//   Each octet is a number, "*" (0-255) or a range "a-b".
//     10.46.*.125        every .125 in 10.46.0.0/16
//     10.46.1-20.*       10.46.1.0 to 10.46.20.255
//   In an exclusion (a token starting with "!", or a pattern exclude) a
//   pattern may give only the trailing octets, matched against the end of
//   each address:
//     !*.2               any address ending in .2
//     !*.0-9             any address whose last octet is 0-9
//   An exclusion can also be a plain address, CIDR or range:
//     !10.46.5.0/24
//
// Tokens are separated by commas or whitespace, so
// "10.46.0.0/16 !*.2 !*.4" and "10.46.0.0/16, !*.2, !*.4" are the same.
// A spec with no pattern syntax at all is returned untouched - the
// expansion is only ever applied to a spec that asks for it.

interface OctetRange {
  lo: number;
  hi: number;
}

export interface AddressPattern {
  // Most significant first. Fewer than four means "the trailing octets".
  octets: OctetRange[];
}

// How many addresses a pattern exclusion may be checked against: a /12.
// Each address is tested one by one, so this bounds the work, and a
// target this large expands far past what one masscan argument can carry
// anyway.
export const MAX_PATTERN_ADDRESSES = 1 << 20;

function parseOctet(part: string): OctetRange | null {
  if (part === "*") return { lo: 0, hi: 255 };
  const range = /^(\d{1,3})-(\d{1,3})$/.exec(part);
  if (range) {
    const lo = Number(range[1]);
    const hi = Number(range[2]);
    return lo <= hi && hi <= 255 ? { lo, hi } : null;
  }
  if (/^\d{1,3}$/.test(part)) {
    const n = Number(part);
    return n <= 255 ? { lo: n, hi: n } : null;
  }
  return null;
}

// null unless text is a pattern - at least one "*" or octet range, so a
// plain address is never mistaken for one. allowSuffix permits fewer than
// four octets (exclusions only).
export function parseAddressPattern(text: string, allowSuffix: boolean): AddressPattern | null {
  const parts = text.split(".");
  if (parts.length > 4 || parts.length < (allowSuffix ? 1 : 4)) return null;
  if (!parts.some((p) => p === "*" || p.includes("-"))) return null;
  const octets: OctetRange[] = [];
  for (const part of parts) {
    const octet = parseOctet(part);
    if (!octet) return null;
    octets.push(octet);
  }
  return { octets };
}

export function patternMatches(pattern: AddressPattern, address: number): boolean {
  const offset = 4 - pattern.octets.length;
  for (let i = 0; i < pattern.octets.length; i++) {
    const octet = (address >>> ((3 - (offset + i)) * 8)) & 255;
    if (octet < pattern.octets[i].lo || octet > pattern.octets[i].hi) return false;
  }
  return true;
}

// The address ranges a full four-octet pattern covers. Contiguous in the
// last octet, so a pattern varying only there is a handful of ranges and
// "every .125" is one single-address range per /24.
function patternRanges(pattern: AddressPattern, limit: number): IPv4Range[] | null {
  const [a, b, c, d] = pattern.octets;
  const count = (a.hi - a.lo + 1) * (b.hi - b.lo + 1) * (c.hi - c.lo + 1);
  if (count > limit) return null;
  const out: IPv4Range[] = [];
  for (let x = a.lo; x <= a.hi; x++) {
    for (let y = b.lo; y <= b.hi; y++) {
      for (let z = c.lo; z <= c.hi; z++) {
        const base = ((x * 256 + y) * 256 + z) * 256;
        out.push({ start: base + d.lo, end: base + d.hi });
      }
    }
  }
  return out;
}

function mergeRanges(ranges: IPv4Range[]): IPv4Range[] {
  const sorted = [...ranges].sort((p, q) => p.start - q.start);
  const out: IPv4Range[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r.start <= last.end + 1) last.end = Math.max(last.end, r.end);
    else out.push({ ...r });
  }
  return out;
}

function subtractRanges(targets: IPv4Range[], excl: IPv4Range[]): IPv4Range[] {
  const ex = mergeRanges(excl);
  const out: IPv4Range[] = [];
  for (const t of mergeRanges(targets)) {
    let cur = t.start;
    for (const x of ex) {
      if (x.end < cur || x.start > t.end) continue;
      if (x.start > cur) out.push({ start: cur, end: x.start - 1 });
      cur = x.end + 1;
      if (cur > t.end) break;
    }
    if (cur <= t.end) out.push({ start: cur, end: t.end });
  }
  return out;
}

// Keeps the addresses no pattern matches, rebuilt as ranges. One address
// at a time - bounded by MAX_PATTERN_ADDRESSES, checked by the caller.
function filterByPatterns(ranges: IPv4Range[], patterns: AddressPattern[], keepMatches: boolean): IPv4Range[] {
  const out: IPv4Range[] = [];
  for (const r of ranges) {
    let runStart = -1;
    for (let a = r.start; a <= r.end; a++) {
      const hit = patterns.some((p) => patternMatches(p, a));
      const keep = keepMatches ? hit : !hit;
      if (keep && runStart < 0) runStart = a;
      if (!keep && runStart >= 0) {
        out.push({ start: runStart, end: a - 1 });
        runStart = -1;
      }
    }
    if (runStart >= 0) out.push({ start: runStart, end: r.end });
  }
  return out;
}

function size(ranges: IPv4Range[]): number {
  return ranges.reduce((n, r) => n + r.end - r.start + 1, 0);
}

function formatRanges(ranges: IPv4Range[]): string[] {
  return ranges.map((r) => (r.start === r.end ? intToIPv4(r.start) : `${intToIPv4(r.start)}-${intToIPv4(r.end)}`));
}

function tokenize(spec: string): string[] {
  return spec
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

// Whether a target spec uses pattern syntax at all - an exclusion, a
// wildcard, or an octet range. A full start-end range ("10.0.0.1-
// 10.0.0.9") is not one: split on dots it has seven parts, not four.
export function isTargetPattern(spec: string): boolean {
  return tokenize(spec).some((t) => t.startsWith("!") || parseAddressPattern(t, false) !== null);
}

export type PatternExpansion =
  | { ok: true; spec: string; expanded: boolean; addresses: number | null }
  | { ok: false; error: string };

// A target spec with patterns, as the plain spec it stands for. Anything
// that is not IPv4 (a hostname, an IPv6 address) passes through as it is;
// exclusions apply to the IPv4 part only.
export function expandTargetPattern(spec: string): PatternExpansion {
  const trimmed = spec.trim();
  if (!isTargetPattern(trimmed)) return { ok: true, spec: trimmed, expanded: false, addresses: null };

  const include: IPv4Range[] = [];
  const passthrough: string[] = [];
  const excludeRanges: IPv4Range[] = [];
  const excludePatterns: AddressPattern[] = [];

  for (const token of tokenize(trimmed)) {
    if (token.startsWith("!")) {
      const body = token.slice(1);
      const ranges = parseTargetSpecRanges(body);
      const pattern = ranges ? null : parseAddressPattern(body, true);
      if (ranges) excludeRanges.push(...ranges);
      else if (pattern) excludePatterns.push(pattern);
      else return { ok: false, error: `"${token}" is not an address, range, CIDR or pattern to exclude` };
      continue;
    }
    const pattern = parseAddressPattern(token, false);
    if (pattern) {
      const ranges = patternRanges(pattern, MAX_PATTERN_ADDRESSES);
      if (!ranges) return { ok: false, error: `"${token}" covers too many addresses for one scan` };
      include.push(...ranges);
      continue;
    }
    const ranges = parseTargetSpecRanges(token);
    if (ranges) include.push(...ranges);
    else passthrough.push(token);
  }

  if (include.length === 0 && passthrough.length === 0) {
    return { ok: false, error: "the target only excludes - give the range to scan as well, e.g. 10.46.0.0/16 !*.2" };
  }

  let result = subtractRanges(include, excludeRanges);
  if (excludePatterns.length > 0) {
    if (size(result) > MAX_PATTERN_ADDRESSES) {
      return { ok: false, error: "a pattern exclusion can only be applied to at most a /12 worth of addresses - narrow the range" };
    }
    result = mergeRanges(filterByPatterns(result, excludePatterns, false));
  }
  if (result.length === 0 && passthrough.length === 0) {
    return { ok: false, error: "the pattern leaves no address to scan" };
  }

  const expanded = [...formatRanges(result), ...passthrough].join(",");
  if (expanded.length > MAX_TARGET_SPEC_LENGTH) {
    return {
      ok: false,
      error: `the pattern expands to ${Math.round(expanded.length / 1024)} KB of targets, more than one scan can take (${MAX_TARGET_SPEC_LENGTH / 1024} KB) - narrow the range or split it into several scans`,
    };
  }
  return { ok: true, spec: expanded, expanded: true, addresses: passthrough.length === 0 ? size(result) : null };
}

// A pattern exclude ("in 10.46.0.0/16, every *.2") as the concrete entries
// a scanner's exclude list takes. Bounded the same way as a target
// pattern; the scope is required so the list stays bounded too.
export const MAX_EXCLUDE_PATTERN_SCOPE = 1 << 20;

export type ExcludePatternValue = { scope: IPv4Range; scopeText: string; pattern: AddressPattern; patternText: string };

// The stored form of a pattern exclude: "<scope CIDR or range> <pattern>",
// e.g. "10.46.0.0/16 *.2". One string so the existing (kind, value)
// uniqueness covers it - the same pattern in two scopes is two rules.
export function parseExcludePatternValue(value: string): ExcludePatternValue | { error: string } {
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 2) return { error: 'write it as "<range> <pattern>", e.g. "10.46.0.0/16 *.2"' };
  const [scopeText, patternText] = parts;
  const scopes = parseTargetSpecRanges(scopeText);
  if (!scopes || scopes.length !== 1) return { error: `"${scopeText}" is not a single IPv4 CIDR or range` };
  const scope = scopes[0];
  if (scope.end - scope.start + 1 > MAX_EXCLUDE_PATTERN_SCOPE) return { error: "the range can be at most a /12" };
  const pattern = parseAddressPattern(patternText, true);
  if (!pattern) {
    return { error: `"${patternText}" is not a pattern - use * or a-b in at least one octet, e.g. *.2 (a single address is an ordinary IP exclude)` };
  }
  return { scope, scopeText, pattern, patternText };
}

export function expandExcludePattern(value: string): string[] {
  const parsed = parseExcludePatternValue(value);
  if ("error" in parsed) return [];
  return formatRanges(mergeRanges(filterByPatterns([parsed.scope], [parsed.pattern], true)));
}

export function countExcludePattern(value: string): number {
  const parsed = parseExcludePatternValue(value);
  if ("error" in parsed) return 0;
  return size(filterByPatterns([parsed.scope], [parsed.pattern], true));
}
