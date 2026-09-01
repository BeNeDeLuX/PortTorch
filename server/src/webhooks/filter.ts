// Severity names, weakest first. nuclei's own scale plus "unknown", which
// it also emits - treated as the weakest rather than dropped, so a
// finding is never silently withheld because its severity was unusual.
const SEVERITY_ORDER = ["unknown", "info", "low", "medium", "high", "critical"];

export interface ChannelFilters {
  filter_scanner_agent_ids: string[];
  filter_tags: string[];
  min_severity: string | null;
}

// What is known about the thing being alerted on. Every field is
// optional, and absence genuinely means "not applicable to this event"
// rather than "no match" - see shouldDeliver.
export interface AlertContext {
  scannerAgentId?: string | null;
  hostTags?: string[] | null;
  severity?: string | null;
}

export function severityRank(severity: string | null | undefined): number {
  if (!severity) return -1;
  const index = SEVERITY_ORDER.indexOf(severity.toLowerCase());
  // An unrecognised severity ranks above everything, so a channel with a
  // minimum set still receives it. Being told about something whose
  // severity we couldn't classify is the safe direction to fail.
  return index === -1 ? SEVERITY_ORDER.length : index;
}

// Whether one channel should receive one alert.
//
// The load-bearing rule: a filter only ever applies when the alert
// actually carries the thing being filtered on. A tag filter narrows
// host events; it does not swallow scanner.offline or
// scan_queue.backlog, which are about the fleet and carry no host at all.
// The alternative - treating "no host" as "no match" - would mean an
// operator who narrowed the noisy host alerts silently lost the
// infrastructure ones, which are the alerts that matter most.
export function shouldDeliver(filters: ChannelFilters, context: AlertContext): boolean {
  if (filters.filter_scanner_agent_ids.length > 0 && context.scannerAgentId) {
    if (!filters.filter_scanner_agent_ids.includes(context.scannerAgentId)) return false;
  }

  if (filters.filter_tags.length > 0 && context.hostTags) {
    // Any-of, not all-of: a channel listing prod and dmz means "either",
    // which is what a list of places reads as.
    const has = context.hostTags.some((tag) => filters.filter_tags.includes(tag));
    if (!has) return false;
  }

  if (filters.min_severity && context.severity) {
    if (severityRank(context.severity) < severityRank(filters.min_severity)) return false;
  }

  return true;
}
