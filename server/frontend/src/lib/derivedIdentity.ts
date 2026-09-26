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
  // The eight services nmap can elicit an NTLM message from. They answer
  // both a name and the exact Windows build (see lib/windowsBuilds.ts),
  // so the same labels serve the hostname marker and the version badge.
  "rdp-ntlm-info": "from NTLM over RDP (rdp-ntlm-info)",
  "http-ntlm-info": "from NTLM over HTTP (http-ntlm-info)",
  "smtp-ntlm-info": "from NTLM over SMTP (smtp-ntlm-info)",
  "imap-ntlm-info": "from NTLM over IMAP (imap-ntlm-info)",
  "pop3-ntlm-info": "from NTLM over POP3 (pop3-ntlm-info)",
  "nntp-ntlm-info": "from NTLM over NNTP (nntp-ntlm-info)",
  "telnet-ntlm-info": "from NTLM over Telnet (telnet-ntlm-info)",
  "ms-sql-ntlm-info": "from NTLM over MS-SQL (ms-sql-ntlm-info)",
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
