// A device's own product and firmware version, from the SNMP sysDescr the
// probe already reads (snmp-sysdescr's first line). Switches, access
// points, UPS cards and printers often answer nothing nmap can version,
// and this string is where their firmware is.
//
// Only shapes that carry a version are read. A sysDescr without one is a
// free-text label unique to the device, and adding it to the software
// inventory would make one row per device out of noise.

export interface Firmware {
  product: string;
  version: string;
}

const VERSION = String.raw`v?(\d+(?:\.\d+){1,4}(?:[-_.][0-9A-Za-z]+)*)`;

export function parseSysDescr(output: string): Firmware | null {
  const line = output.split("\n").map((l) => l.trim()).find((l) => l !== "") ?? "";
  if (!line || line.length > 400) return null;

  // Windows: "Hardware: ... Software: Windows Version 6.3 (Build 9600 Multiprocessor Free)"
  const win = /Software:\s*Windows(?: Version)? ([\d.]+) \(Build (\d+)/i.exec(line);
  if (win) return { product: "Windows", version: `${win[1]}.${win[2]}` };

  // Cisco IOS / IOS-XE / NX-OS and the many vendors copying the shape:
  // "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE7, RELEASE SOFTWARE (fc2)"
  const cisco = /^(Cisco (?:IOS(?:[- ]XE)?|NX-OS|Adaptive Security Appliance)).*?\bVersion ([\w.()-]+)/i.exec(line);
  if (cisco) return { product: cisco[1].replace(/\s+/g, " "), version: cisco[2].replace(/,$/, "") };

  // Linux: "Linux fw01 5.15.0-91-generic #101-Ubuntu SMP ..."
  const linux = /^Linux \S+ (\d+\.\d+[\w.+-]*)/.exec(line);
  if (linux) return { product: "Linux kernel", version: linux[1] };

  // "<model> <version>" or "<model>, <version>" - Ubiquiti, many
  // embedded devices: "UAP-AC-Pro-Gen2 6.8.2.15592",
  // "USW-Enterprise-8-PoE, 7.5.15.17146".
  const trailing = new RegExp(String.raw`^(.{2,80}?)[,;]?\s+${VERSION}$`).exec(line);
  if (trailing && /[A-Za-z]/.test(trailing[1])) return { product: trailing[1].trim(), version: trailing[2] };

  return null;
}

// Numeric comparison of dotted versions, so "7.5.15" is newer than "7.5.9".
// Non-numeric parts compare as text. Used to mark a version as older than
// the newest of the same product seen in the fleet.
export function compareVersions(a: string, b: string): number {
  // Runs of digits and runs of letters, so Cisco's "SE7" and "SE12"
  // compare as SE then 7 against SE then 12.
  const pa = a.match(/\d+|[A-Za-z]+/g) ?? [];
  const pb = b.match(/\d+|[A-Za-z]+/g) ?? [];
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "";
    const y = pb[i] ?? "";
    const nx = /^\d+$/.test(x) ? Number(x) : null;
    const ny = /^\d+$/.test(y) ? Number(y) : null;
    if (nx !== null && ny !== null) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) {
      if (x === "") return -1;
      if (y === "") return 1;
      return x.localeCompare(y);
    }
  }
  return 0;
}

// Whether a version string is the comparable dotted kind - "behind the
// fleet" is only claimed between versions like that, never between
// "1.0" and "3.X - 4.X".
export function isComparableVersion(v: string): boolean {
  // A suffix may follow directly - OpenSSH writes "8.4p1" - or after a
  // separator; what is excluded is prose like "3.X - 4.X" or "or later".
  return /^v?\d+(\.\d+)+([-_.(]?[A-Za-z0-9][\w.)-]*)?$/.test(v.trim());
}
