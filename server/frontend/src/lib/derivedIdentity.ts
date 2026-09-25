// How a derived name or address is labelled wherever one is shown.
//
// The point of surfacing the source at all: a name from DNS and a name a
// machine claims for itself are different kinds of fact, and a reader who
// cannot tell them apart will act on the weaker one as if it were the
// stronger. On a real fleet the two disagreed - PTR said
// "filer01.example.internal", the machine answered "FILER02" over SMB.
export const IDENTITY_SOURCE_LABEL: Record<string, string> = {
  "rdp-certificate": "from the RDP certificate",
  "smb-os-discovery": "from SMB (smb-os-discovery)",
  nbstat: "from NetBIOS (nbstat)",
};

export function identitySourceLabel(source: string | null): string {
  if (!source) return "derived from scan data";
  return IDENTITY_SOURCE_LABEL[source] ?? `from ${source}`;
}

// The name to show for a host: the real one when there is one, otherwise
// whatever the scan worked out, flagged as derived. Never silently
// substitutes - the caller gets `derived` so it can mark it.
export function displayHostname(host: {
  hostname: string | null;
  derived_hostname: string | null;
  derived_hostname_source: string | null;
}): { name: string | null; derived: boolean; source: string | null } {
  if (host.hostname) return { name: host.hostname, derived: false, source: null };
  if (host.derived_hostname) {
    return { name: host.derived_hostname, derived: true, source: host.derived_hostname_source };
  }
  return { name: null, derived: false, source: null };
}
