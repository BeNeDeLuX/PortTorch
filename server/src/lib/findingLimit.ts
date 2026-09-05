// The fleet-wide finding pages (Vulnerabilities, Web Findings,
// Certificates, SSH Keys) each return their whole result set in one
// response, unpaginated, because their filtering and sorting are
// deliberately client-side: the triage filter, the search box, the
// column sort and the bulk-select all operate on the complete set, and
// moving them server-side would be a much larger change for pages that
// are read far more often than they are large.
//
// That is fine until it isn't. Vulnerabilities returns one row per
// (host, port, CVE), so a fleet with a well-populated CVE cache reaches
// five figures without anything being wrong - and the page then ships
// and renders all of them.
//
// So: a hard ceiling, and an honest flag when it is reached. Truncating
// silently would be worse than not truncating at all, because a page
// that quietly omits findings is a page that gets trusted for something
// it can no longer do.
export const FINDING_LIMIT = 5000;

export interface LimitedResult<T> {
  items: T[];
  total: number;
  // True when `total` exceeded the ceiling and `items` is only the first
  // FINDING_LIMIT of them - the page says so rather than looking complete.
  truncated: boolean;
  limit: number;
}

export function limitFindings<T>(rows: T[]): LimitedResult<T> {
  return {
    items: rows.length > FINDING_LIMIT ? rows.slice(0, FINDING_LIMIT) : rows,
    total: rows.length,
    truncated: rows.length > FINDING_LIMIT,
    limit: FINDING_LIMIT,
  };
}
