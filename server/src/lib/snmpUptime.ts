// How long a device has been up, from what the SNMP probe already reads.
//
// Two sources, in this order:
//
//   - snmp-info's SNMPv3 engine time ("snmpEngineTime: 73d00h10m33s") and
//     its boot counter ("snmpEngineBoots: 2"). The time never wraps, and
//     the counter makes a reboot a fact rather than an inference. An
//     agent reporting "0s" and boots 0 has an unconfigured engine, which
//     says nothing - unknown, not "just booted".
//   - snmp-sysdescr's sysUpTime ("System uptime: 72d22h08m54.00s
//     (630053400 timeticks)"), for SNMPv1/v2c-only devices. Read from the
//     tick count, which is exact. It is a 32-bit counter of hundredths of
//     a second and wraps every 497.1 days - so on exactly the devices this
//     field exists to find (up for years, never patched), it reads short.
//     reconcileUptime below refuses to call that wrap a reboot.
//
// The engine time strictly counts since the engine last (re)initialised,
// which is a reboot or, rarely, an SNMP configuration change - close
// enough to "up since" to be useful, and said so in the UI.

export type UptimeSource = "snmp-engine" | "snmp-sysuptime";

export interface UptimeReading {
  uptimeSeconds: number;
  source: UptimeSource;
  engineBoots: number | null;
}

export const SYSUPTIME_WRAP_SECONDS = 2 ** 32 / 100;

// nmap's own duration format: "73d00h10m33s", "17h31m31s", "51.70s".
export function parseNmapDuration(text: string): number | null {
  const m = /^\s*(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?\s*$/.exec(text);
  if (!m || text.trim() === "") return null;
  const [, d, h, min, s] = m;
  if (d === undefined && h === undefined && min === undefined && s === undefined) return null;
  return Number(d ?? 0) * 86400 + Number(h ?? 0) * 3600 + Number(min ?? 0) * 60 + Number(s ?? 0);
}

export function parseSnmpInfoUptime(output: string): UptimeReading | null {
  const time = /snmpEngineTime:\s*([^\n]+)/.exec(output);
  const boots = /snmpEngineBoots:\s*(\d+)/.exec(output);
  if (!time) return null;
  const seconds = parseNmapDuration(time[1]);
  const engineBoots = boots ? Number(boots[1]) : null;
  if (seconds === null || seconds <= 0 || engineBoots === 0) return null;
  return { uptimeSeconds: seconds, source: "snmp-engine", engineBoots };
}

export function parseSysUptime(output: string): UptimeReading | null {
  const ticks = /System uptime:[^\n]*\((\d+) timeticks\)/.exec(output);
  if (ticks) {
    const seconds = Number(ticks[1]) / 100;
    return seconds > 0 ? { uptimeSeconds: seconds, source: "snmp-sysuptime", engineBoots: null } : null;
  }
  const text = /System uptime:\s*([^\s(]+)/.exec(output);
  const seconds = text ? parseNmapDuration(text[1]) : null;
  return seconds && seconds > 0 ? { uptimeSeconds: seconds, source: "snmp-sysuptime", engineBoots: null } : null;
}

export function uptimeFromScripts(scripts: Array<{ id: string; output: string }>): UptimeReading | null {
  for (const s of scripts) {
    if (s.id === "snmp-info") {
      const r = parseSnmpInfoUptime(s.output);
      if (r) return r;
    }
  }
  for (const s of scripts) {
    if (s.id === "snmp-sysdescr") {
      const r = parseSysUptime(s.output);
      if (r) return r;
    }
  }
  return null;
}

export interface StoredUptime {
  bootTime: Date | null;
  source: string | null;
  engineBoots: number | null;
}

// What to store from a new reading, and whether it is a reboot.
//
// A reboot is: the engine boot counter went up; or, without a counter,
// the boot time moved later by more than REBOOT_TOLERANCE (clocks and
// probe timing jitter by seconds, never by half an hour). A sysUpTime
// reading that is exactly what the 497-day wrap would produce is the
// counter wrapping, not a reboot: the stored boot time is kept, since it
// is still the right answer.
export const REBOOT_TOLERANCE_SECONDS = 30 * 60;

export function reconcileUptime(
  prev: StoredUptime,
  reading: UptimeReading,
  observedAt: Date
): { bootTime: Date; source: UptimeSource; engineBoots: number | null; rebooted: boolean; wrapped: boolean } {
  const bootTime = new Date(observedAt.getTime() - reading.uptimeSeconds * 1000);
  if (!prev.bootTime) return { bootTime, source: reading.source, engineBoots: reading.engineBoots, rebooted: false, wrapped: false };

  if (reading.engineBoots !== null && prev.engineBoots !== null) {
    return { bootTime, source: reading.source, engineBoots: reading.engineBoots, rebooted: reading.engineBoots > prev.engineBoots, wrapped: false };
  }

  const movedLater = (bootTime.getTime() - prev.bootTime.getTime()) / 1000 > REBOOT_TOLERANCE_SECONDS;
  if (movedLater && reading.source === "snmp-sysuptime") {
    // After a wrap the counter reads exactly the old uptime modulo the
    // wrap period - a real reboot reads anything else. So a device up
    // for 600 days that really did reboot is still reported as one.
    const previousUptime = (observedAt.getTime() - prev.bootTime.getTime()) / 1000;
    const expectedAfterWrap = previousUptime % SYSUPTIME_WRAP_SECONDS;
    if (previousUptime >= SYSUPTIME_WRAP_SECONDS && Math.abs(reading.uptimeSeconds - expectedAfterWrap) <= REBOOT_TOLERANCE_SECONDS) {
      return { bootTime: prev.bootTime, source: (prev.source as UptimeSource) ?? reading.source, engineBoots: prev.engineBoots, rebooted: false, wrapped: true };
    }
  }
  return { bootTime, source: reading.source, engineBoots: reading.engineBoots ?? prev.engineBoots, rebooted: movedLater, wrapped: false };
}
