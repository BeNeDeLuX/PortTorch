// Turning an uploaded file of addresses into the comma-separated target
// spec the Target field already accepts.
//
// This is deliberately a convenience in front of that field rather than a
// new upload endpoint: masscan's own grammar takes a comma-separated
// list, the scanner's own `--targets-file` flag already works by joining
// lines with commas, and scan_requests.target_spec has always carried
// whatever string was typed. So the file never leaves the browser, the
// operator sees exactly what will be scanned before submitting, and every
// other control on the page (Estimate time, the profile pickers,
// priority) keeps working with no knowledge that a file was involved.

// The hard ceiling, and it is not arbitrary. RunMasscan passes the whole
// target spec as a *single* argv entry, and Linux caps one argument at
// MAX_ARG_STRLEN - 32 pages, 131072 bytes. Measured against real masscan
// 1.3.2 rather than assumed: 8200 addresses (92 KB) ran fine, 20000
// (229 KB) failed before masscan even started, with the shell's own
// "Argument list too long" and no message that points at the list. Half
// that ceiling leaves room for the rest of the command line and still
// allows roughly four thousand worst-case addresses.
export const MAX_TARGET_SPEC_LENGTH = 65536;

export interface TargetListResult {
  // The joined spec, ready for the Target field.
  spec: string;
  entries: string[];
  // Exact repeats that were dropped - worth reporting rather than
  // silently fixing, since a list that repeats itself usually means two
  // sources were concatenated.
  duplicates: number;
  // Everything that matched none of the accepted shapes, with the line it
  // came from so it can be found in the file.
  errors: Array<{ line: number; value: string }>;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIPv4(value: string): boolean {
  const m = IPV4.exec(value);
  return m !== null && m.slice(1).every((octet) => Number(octet) <= 255 && String(Number(octet)) === octet);
}

function isIPv4Cidr(value: string): boolean {
  const [address, prefix, ...rest] = value.split("/");
  if (rest.length > 0 || prefix === undefined) return false;
  return isIPv4(address) && /^\d{1,2}$/.test(prefix) && Number(prefix) <= 32;
}

function isIPv4Range(value: string): boolean {
  const parts = value.split("-");
  return parts.length === 2 && parts.every(isIPv4);
}

// The browser's own URL parser is the IPv6 validator, rather than a
// hand-written regex: IPv6 has compression, embedded IPv4 and zone
// syntax, and a regex that gets those subtly wrong rejects addresses that
// are perfectly valid. The bracket form is exactly what a URL host
// accepts. Deliberately not used for IPv4 - there the URL spec's own host
// parser accepts legacy shorthands and would silently rewrite
// "192.168.1" into "192.168.0.1", so that one stays a strict regex.
function isIPv6(value: string): boolean {
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}

function isIPv6Cidr(value: string): boolean {
  const idx = value.lastIndexOf("/");
  if (idx === -1) return false;
  const prefix = value.slice(idx + 1);
  return isIPv6(value.slice(0, idx)) && /^\d{1,3}$/.test(prefix) && Number(prefix) <= 128;
}

// A hostname is a legitimate target (the scanner resolves it), so a file
// may hold names - under two conditions, both of which exist because the
// scanner fails a scan *closed* when a name does not resolve, so one
// stray word in a file costs the whole scan.
//
// Letters must actually be present, or "192.168.0.999" would pass as a
// hostname and a typo'd address would reach the scanner as a name.
//
// And a dot is required, which is the rule a first draft of this got
// wrong: a bare label like "not" is a perfectly valid hostname, so the
// line "not an address" parsed as three targets rather than as an error.
// In a file of addresses a bare word is a CSV header or prose far more
// often than it is a short internal name, and the Target field itself
// still takes one typed by hand.
function isHostname(value: string): boolean {
  if (!/[a-zA-Z]/.test(value)) return false;
  if (!value.includes(".")) return false;
  if (value.length > 253) return false;
  return value.split(".").every((label) => /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
}

export function isTargetEntry(value: string): boolean {
  return isIPv4(value) || isIPv4Cidr(value) || isIPv4Range(value) || isIPv6(value) || isIPv6Cidr(value) || isHostname(value);
}

// Separators follow the scanner's own --targets-file conventions (one
// entry per line, "#" comments) *and* the comma-separated form the field
// itself takes, because both shapes turn up in a file people already
// have. Colons are never a separator - an IPv6 address is full of them.
export function parseTargetList(text: string): TargetListResult {
  const entries: string[] = [];
  const seen = new Set<string>();
  const errors: TargetListResult["errors"] = [];
  let duplicates = 0;

  text.split(/\r?\n/).forEach((rawLine, index) => {
    const line = rawLine.split("#")[0];
    for (const token of line.split(/[,;\s]+/)) {
      const value = token.trim();
      if (!value) continue;
      if (!isTargetEntry(value)) {
        errors.push({ line: index + 1, value });
        continue;
      }
      const key = value.toLowerCase();
      if (seen.has(key)) {
        duplicates++;
        continue;
      }
      seen.add(key);
      entries.push(value);
    }
  });

  return { spec: entries.join(","), entries, duplicates, errors };
}
