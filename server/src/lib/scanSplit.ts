import crypto from "crypto";
import net from "net";
import { intToIPv4, parseTargetSpecRanges, type IPv4Range } from "./ipRange";
import { MAX_TARGET_SPEC_LENGTH } from "./targetSpec";

// Splitting one scan's target across several scanners, so the runtime
// drops with the number of scanners.
//
// **The same address always goes to the same scanner.** Host identity is
// (ip, scanner_agent_id), so a split that moved an address from one
// scanner to another between runs would leave a second host row for it
// behind - the duplicate-coverage problem Fleet Health already reports.
// Each block of addresses is therefore assigned by rendezvous hashing
// (highest hash of scanner id + block wins): deterministic, independent of
// the rest of the target, and when a scanner joins or leaves the set only
// the blocks that scanner wins or held move - not everything.
//
// The block is a /28 (16 addresses), small enough that even a single /24
// spreads across several scanners, which is the case someone splitting a
// scan most expects to work. Each part becomes one masscan argument, so
// its spec must stay under MAX_TARGET_SPEC_LENGTH; a very large target
// (beyond roughly a /15) produces more scattered /28 ranges than that, and
// falls back to /24 and then /20 blocks. Those are still deterministic for
// that target, but a given address may then belong to a different scanner
// than when it is scanned as part of a smaller target - documented rather
// than hidden, since a fallback is better than refusing the scan.
//
// Parts that are not IPv4 - an IPv6 address, a DNS hostname - are
// assigned whole, by the same hash over the part itself.

export const SPLIT_BLOCK_PREFIXES = [28, 24, 20] as const;

// How many scanners one scan may be split across. A sanity bound, not a
// design limit - more scanners than this reaching one network is not a
// real fleet.
export const MAX_SPLIT_SCANNERS = 32;

// More blocks than this is not worth hashing one by one: the result would
// be far too long for one masscan argument anyway.
const MAX_BLOCKS = 1 << 16;

export interface SplitPart {
  scannerAgentId: string;
  targetSpec: string;
  // IPv4 addresses in this part, or null when it holds something that
  // cannot be counted (a hostname).
  addresses: number | null;
}

export type SplitResult =
  | { ok: true; parts: SplitPart[]; blockPrefix: number | null }
  | { ok: false; error: string };

function score(scannerId: string, key: string): bigint {
  return crypto.createHash("sha256").update(`${scannerId}|${key}`).digest().readBigUInt64BE(0);
}

// The scanner that owns a block. Ties are broken by id so the answer
// never depends on the order the scanners were passed in.
export function ownerOf(key: string, scannerIds: string[]): string {
  let best = scannerIds[0];
  let bestScore = -1n;
  for (const id of scannerIds) {
    const s = score(id, key);
    if (s > bestScore || (s === bestScore && id < best)) {
      best = id;
      bestScore = s;
    }
  }
  return best;
}

function mergeRanges(ranges: IPv4Range[]): IPv4Range[] {
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const out: IPv4Range[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r.start <= last.end + 1) {
      last.end = Math.max(last.end, r.end);
    } else {
      out.push({ ...r });
    }
  }
  return out;
}

function formatRange(r: IPv4Range): string {
  return r.start === r.end ? intToIPv4(r.start) : `${intToIPv4(r.start)}-${intToIPv4(r.end)}`;
}

export function splitTargetSpec(targetSpec: string, scannerIds: string[]): SplitResult {
  const ids = [...new Set(scannerIds)];
  if (ids.length === 0) return { ok: false, error: "no scanner selected" };

  const tokens = targetSpec
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  if (tokens.length === 0) return { ok: false, error: "empty target" };

  // A single scanner is not a split: the target goes through exactly as
  // typed, so nothing about an ordinary scan changes shape.
  if (ids.length === 1) {
    const ranges = parseTargetSpecRanges(targetSpec);
    return {
      ok: true,
      blockPrefix: null,
      parts: [
        {
          scannerAgentId: ids[0],
          targetSpec: targetSpec.trim(),
          addresses: ranges ? ranges.reduce((n, r) => n + r.end - r.start + 1, 0) : null,
        },
      ],
    };
  }

  const ipv4: IPv4Range[] = [];
  const opaque: string[] = [];
  for (const token of tokens) {
    const ranges = parseTargetSpecRanges(token);
    if (ranges) ipv4.push(...ranges);
    else opaque.push(net.isIP(token) === 6 ? token.toLowerCase() : token);
  }
  const merged = mergeRanges(ipv4);

  const opaqueByScanner = new Map<string, string[]>();
  for (const token of [...new Set(opaque)]) {
    const owner = ownerOf(`u:${token.toLowerCase()}`, ids);
    opaqueByScanner.set(owner, [...(opaqueByScanner.get(owner) ?? []), token]);
  }

  for (const prefix of SPLIT_BLOCK_PREFIXES) {
    const size = 2 ** (32 - prefix);
    let blocks = 0;
    for (const r of merged) blocks += Math.floor(r.end / size) - Math.floor(r.start / size) + 1;
    if (blocks > MAX_BLOCKS) continue;

    const byScanner = new Map<string, IPv4Range[]>();
    for (const r of merged) {
      for (let base = Math.floor(r.start / size) * size; base <= r.end; base += size) {
        const piece = { start: Math.max(r.start, base), end: Math.min(r.end, base + size - 1) };
        const owner = ownerOf(`v4:${intToIPv4(base)}/${prefix}`, ids);
        const list = byScanner.get(owner) ?? [];
        const last = list[list.length - 1];
        if (last && last.end + 1 === piece.start) last.end = piece.end;
        else list.push(piece);
        byScanner.set(owner, list);
      }
    }

    const parts: SplitPart[] = [];
    for (const id of ids) {
      const ranges = byScanner.get(id) ?? [];
      const others = opaqueByScanner.get(id) ?? [];
      if (ranges.length === 0 && others.length === 0) continue;
      parts.push({
        scannerAgentId: id,
        targetSpec: [...ranges.map(formatRange), ...others].join(","),
        addresses: others.some((o) => net.isIP(o) !== 6) ? null : ranges.reduce((n, r) => n + r.end - r.start + 1, 0) + others.length,
      });
    }
    if (parts.every((p) => p.targetSpec.length <= MAX_TARGET_SPEC_LENGTH)) {
      return { ok: true, parts, blockPrefix: merged.length > 0 ? prefix : null };
    }
  }
  return {
    ok: false,
    error: "this target is too large to split into parts a scanner can take in one argument - split it into several scans",
  };
}

// The masscan rate each part runs at. With rate splitting on, the
// requested rate is the total for the whole group - three scanners at a
// third of it each push the same packets per second at the target network
// as one scanner would, just from three places at once.
export function partRate(rate: number | null | undefined, parts: number, split: boolean): number | null {
  if (rate === null || rate === undefined) return null;
  if (!split || parts <= 1) return rate;
  return Math.max(1, Math.floor(rate / parts));
}
