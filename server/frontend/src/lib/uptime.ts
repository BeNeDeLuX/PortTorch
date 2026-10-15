// How long a device has been up, from the boot time the webserver derives
// from SNMP (server/src/lib/snmpUptime.ts). Computed at display time from
// the boot time, so it stays right between scans.

// Past this, a device has almost certainly missed patches that need a
// reboot - firmware, kernels, most OS updates. A display heuristic, not a
// policy: some appliances are patched without one.
export const LONG_UPTIME_DAYS = 180;

export function uptimeDays(bootTime: string | null): number | null {
  if (!bootTime) return null;
  const ms = Date.now() - new Date(bootTime).getTime();
  return ms >= 0 ? Math.floor(ms / 86_400_000) : null;
}

export function uptimeLabel(bootTime: string | null): string | null {
  const days = uptimeDays(bootTime);
  if (days === null) return null;
  if (days === 0) {
    const hours = Math.floor((Date.now() - new Date(bootTime!).getTime()) / 3_600_000);
    return `${hours} h`;
  }
  return days >= 365 ? `${days} days (${(days / 365).toFixed(1)} years)` : `${days} day${days === 1 ? "" : "s"}`;
}

export const UPTIME_SOURCE_LABEL: Record<string, string> = {
  "snmp-engine": "from the SNMPv3 engine time (snmp-info) - counts since the SNMP engine last started, normally the last reboot",
  "snmp-sysuptime": "from sysUpTime (snmp-sysdescr) - this counter wraps every 497 days, which PortTorch accounts for once it has seen the device before the wrap",
};
