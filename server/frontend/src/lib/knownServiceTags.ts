// Mirrors the tag names server/src/lib/serviceTags.ts's RULES table can
// auto-add on ingest - a frontend-only copy used purely to render a
// visual "this was set automatically" cue on Host Detail, same
// independent-copy precedent as scanProfiles/knownNseScripts.ts (there,
// for validation; here, for display only - a name collision with a
// user's own manually-added tag is harmless, it just also gets the
// auto-tag hint).
export const AUTO_TAG_NAMES = new Set([
  "WebServer",
  "FTP-Server",
  "SSH-Server",
  "Telnet",
  "DNS-Server",
  "RDP",
  "SMB",
  "Mail-Server",
  "LDAP",
  "VNC",
  "MySQL",
  "PostgreSQL",
  "MSSQL",
  "MongoDB",
  "Redis",
  "Docker-API",
  "SNMP",
  "IPMI",
]);

export function isAutoTag(tag: string): boolean {
  return AUTO_TAG_NAMES.has(tag);
}
