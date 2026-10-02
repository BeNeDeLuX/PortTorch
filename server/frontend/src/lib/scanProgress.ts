import type { ScanProgressCounts } from "../api";

export interface ProgressView {
  // Discovery is still running a block-split target: how many blocks are
  // done. null for a single-pass scan, where masscan reports all hosts at
  // once and there is no meaningful partial figure.
  discovery: { done: number; total: number; percent: number } | null;
  // The host bar, or null while there is no host count to measure
  // against yet.
  hosts: { processed: number; discovered: number; percent: number; final: boolean } | null;
  // Discovery is finished and found nothing to enrich.
  nothingFound: boolean;
}

// The progress bar counts hosts, not ports: the number of hosts nmap has
// to enrich is known the moment discovery reports, while how long each
// takes depends on what it turns out to run. Pure so the edge cases below
// are unit-tested rather than eyeballed:
//
//   - Percentages are floored, so the bar never claims 100% while one
//     host is still being worked on.
//   - While a block-split discovery is still running, the host total is
//     not final - more blocks can add hosts - so the bar says so instead of
//     presenting "10 of 10" as done.
export function progressView(counts: ScanProgressCounts | null): ProgressView {
  if (!counts) return { discovery: null, hosts: null, nothingFound: false };
  const total = Math.max(1, counts.discoveryBlocks);
  const blocksDone = Math.min(counts.discoveryBlocksDone, total);
  const discoveryFinished = blocksDone >= total;

  const discovery = total > 1 && !discoveryFinished
    ? { done: blocksDone, total, percent: Math.floor((blocksDone / total) * 100) }
    : null;

  if (blocksDone === 0) return { discovery, hosts: null, nothingFound: false };
  if (counts.hostsDiscovered === 0) {
    return { discovery, hosts: null, nothingFound: discoveryFinished };
  }
  const processed = Math.min(counts.hostsProcessed, counts.hostsDiscovered);
  return {
    discovery,
    hosts: {
      processed,
      discovered: counts.hostsDiscovered,
      percent: Math.floor((processed / counts.hostsDiscovered) * 100),
      final: discoveryFinished,
    },
    nothingFound: false,
  };
}
