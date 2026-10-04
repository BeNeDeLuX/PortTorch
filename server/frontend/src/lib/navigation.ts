import type { Me } from "../api";

export interface NavItem {
  to: string;
  label: string;
  // Extra words the quick search matches on, for pages whose label is not
  // what someone would type ("dashboard" for Scan Results).
  keywords?: string;
}

export type NavEntry = { kind: "link"; item: NavItem } | { kind: "group"; label: string; items: NavItem[] };

// The main navigation, in one place, because two things read it: the
// header renders it and the quick search (Ctrl+K) offers every page in
// it. Kept apart, a new page added to the menu and forgotten in the search
// would be exactly the drift this prevents. Admin-only entries are left
// out for other roles here, so neither consumer can offer a page whose API
// would only answer 403.
export function navEntries(role: Me["role"]): NavEntry[] {
  const admin = role === "admin";
  const link = (to: string, label: string, keywords?: string): NavEntry => ({ kind: "link", item: { to, label, keywords } });
  return [
    link("/", "Scan Results", "dashboard hosts host list search"),
    {
      kind: "group",
      label: "Scanning",
      items: [
        { to: "/adhoc-scans", label: "Ad-hoc Scans", keywords: "scan now target one-off" },
        { to: "/schedules", label: "Schedule Scans", keywords: "cron recurring interval" },
        { to: "/agents", label: "Scanner Agents", keywords: "scanners queue update" },
        { to: "/scan-history", label: "Scan History", keywords: "finished jobs resume rescan" },
        { to: "/networks", label: "Network Coverage", keywords: "ranges monitored cidr" },
        { to: "/baselines", label: "Baselines", keywords: "approved expected state deviation drift" },
        { to: "/import", label: "Import Scan", keywords: "nmap xml upload" },
        { to: "/saved-searches", label: "Saved Searches", keywords: "alerts filters" },
        ...(admin
          ? [
              { to: "/scan-profiles", label: "Scan Profiles", keywords: "nse scripts" },
              { to: "/nuclei-profiles", label: "Nuclei Profiles", keywords: "templates web" },
              { to: "/excludes", label: "Excludes", keywords: "never scan exclusions" },
            ]
          : []),
      ],
    },
    link("/screenshots", "Screenshots", "gallery web rdp"),
    link("/certificates", "Certificates", "tls ssl expiry"),
    link("/ssh-keys", "SSH Keys", "host keys fingerprints"),
    link("/software", "Software", "inventory versions products"),
    link("/vulnerabilities", "Vulnerabilities", "cve kev epss cvss"),
    link("/web-findings", "Web Findings", "nuclei"),
    link("/digest", "Digest", "changes new hosts"),
    {
      kind: "group",
      label: "Statistics",
      items: [
        { to: "/trends", label: "Trends", keywords: "time series charts" },
        { to: "/scan-stats", label: "Scan Stats", keywords: "composition charts" },
        { to: "/subnets", label: "Subnets", keywords: "networks map heatmap /24" },
      ],
    },
    link("/health", "Health", "fleet health status"),
    ...(admin
      ? [
          {
            kind: "group" as const,
            label: "Admin",
            items: [
              { to: "/webhooks", label: "Webhooks", keywords: "alerts email teams" },
              { to: "/triage-rules", label: "Triage Rules", keywords: "false positive fleet-wide" },
              { to: "/users", label: "Users", keywords: "accounts roles" },
              { to: "/audit", label: "Audit", keywords: "log who did what" },
              { to: "/api-tokens", label: "API Tokens", keywords: "external api" },
              { to: "/settings", label: "Settings", keywords: "configuration smtp retention backup proxy" },
            ],
          },
        ]
      : []),
  ];
}

// Every page as one flat list, with the menu it lives in, for the quick
// search. The account page is reachable from the header's own link
// rather than the menu, so it is added here explicitly.
export function flatPages(role: Me["role"]): (NavItem & { section: string | null })[] {
  const pages: (NavItem & { section: string | null })[] = [];
  for (const entry of navEntries(role)) {
    if (entry.kind === "link") pages.push({ ...entry.item, section: null });
    else for (const item of entry.items) pages.push({ ...item, section: entry.label });
  }
  pages.push({ to: "/account", label: "Account", keywords: "password 2fa preferences theme", section: null });
  return pages;
}
