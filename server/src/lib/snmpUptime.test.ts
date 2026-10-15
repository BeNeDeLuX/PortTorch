import { describe, expect, it } from "vitest";
import { parseNmapDuration, parseSnmpInfoUptime, parseSysUptime, reconcileUptime, SYSUPTIME_WRAP_SECONDS, uptimeFromScripts } from "./snmpUptime";

// Literal outputs from a live deployment.
const SNMP_INFO = `
  enterprise: TP-Link Corporation Limited.
  engineIDFormat: mac
  engineIDData: 9c:a2:f4:ed:64:a9
  snmpEngineBoots: 2
  snmpEngineTime: 73d00h10m33s`;
const UNCONFIGURED = `
  enterprise: netSnmp
  engineIDFormat: unknown
  snmpEngineBoots: 0
  snmpEngineTime: 0s`;
const SYSDESCR = `UAP-AC-Pro-Gen2 6.8.2.15592
  System uptime: 72d22h08m54.00s (630053400 timeticks)`;

const DAY = 86400;

describe("parsing", () => {
  it("reads nmap durations", () => {
    expect(parseNmapDuration("73d00h10m33s")).toBe(73 * DAY + 10 * 60 + 33);
    expect(parseNmapDuration("17h31m31s")).toBe(17 * 3600 + 31 * 60 + 31);
    expect(parseNmapDuration("51.70s")).toBeCloseTo(51.7);
    expect(parseNmapDuration("")).toBeNull();
    expect(parseNmapDuration("soon")).toBeNull();
  });
  it("reads the engine time and boot counter", () => {
    expect(parseSnmpInfoUptime(SNMP_INFO)).toEqual({ uptimeSeconds: 73 * DAY + 633, source: "snmp-engine", engineBoots: 2 });
  });
  it("treats an unconfigured engine as unknown, not as just booted", () => {
    expect(parseSnmpInfoUptime(UNCONFIGURED)).toBeNull();
  });
  it("reads sysUpTime from the exact tick count", () => {
    expect(parseSysUptime(SYSDESCR)).toEqual({ uptimeSeconds: 6300534, source: "snmp-sysuptime", engineBoots: null });
  });
  it("prefers the engine time, falls back to sysUpTime", () => {
    expect(uptimeFromScripts([{ id: "snmp-sysdescr", output: SYSDESCR }, { id: "snmp-info", output: SNMP_INFO }])?.source).toBe("snmp-engine");
    expect(uptimeFromScripts([{ id: "snmp-sysdescr", output: SYSDESCR }, { id: "snmp-info", output: UNCONFIGURED }])?.source).toBe("snmp-sysuptime");
    expect(uptimeFromScripts([{ id: "http-title", output: "x" }])).toBeNull();
  });
});

describe("reconcileUptime", () => {
  const now = new Date("2026-10-13T12:00:00Z");
  const ago = (days: number) => new Date(now.getTime() - days * DAY * 1000);

  it("stores a first reading without calling it a reboot", () => {
    const r = reconcileUptime({ bootTime: null, source: null, engineBoots: null }, { uptimeSeconds: 10 * DAY, source: "snmp-engine", engineBoots: 3 }, now);
    expect(r.bootTime).toEqual(ago(10));
    expect(r.rebooted).toBe(false);
  });
  it("calls a higher boot counter a reboot", () => {
    const r = reconcileUptime({ bootTime: ago(40), source: "snmp-engine", engineBoots: 2 }, { uptimeSeconds: 3600, source: "snmp-engine", engineBoots: 3 }, now);
    expect(r.rebooted).toBe(true);
  });
  it("does not call jitter a reboot", () => {
    const r = reconcileUptime({ bootTime: ago(40), source: "snmp-sysuptime", engineBoots: null }, { uptimeSeconds: 40 * DAY - 60, source: "snmp-sysuptime", engineBoots: null }, now);
    expect(r.rebooted).toBe(false);
  });
  it("calls a sysUpTime reset a reboot", () => {
    const r = reconcileUptime({ bootTime: ago(40), source: "snmp-sysuptime", engineBoots: null }, { uptimeSeconds: 2 * 3600, source: "snmp-sysuptime", engineBoots: null }, now);
    expect(r.rebooted).toBe(true);
    expect(r.bootTime).toEqual(new Date(now.getTime() - 2 * 3600 * 1000));
  });
  it("recognises the 497-day sysUpTime wrap and keeps the real boot time", () => {
    const prevBoot = new Date(now.getTime() - (SYSUPTIME_WRAP_SECONDS + 3 * DAY) * 1000);
    const r = reconcileUptime({ bootTime: prevBoot, source: "snmp-sysuptime", engineBoots: null }, { uptimeSeconds: 3 * DAY, source: "snmp-sysuptime", engineBoots: null }, now);
    expect(r.wrapped).toBe(true);
    expect(r.rebooted).toBe(false);
    expect(r.bootTime).toEqual(prevBoot);
  });
  it("still sees a real reboot of a device that was up past the wrap", () => {
    const prevBoot = new Date(now.getTime() - (SYSUPTIME_WRAP_SECONDS + 3 * DAY) * 1000);
    const r = reconcileUptime({ bootTime: prevBoot, source: "snmp-sysuptime", engineBoots: null }, { uptimeSeconds: 600, source: "snmp-sysuptime", engineBoots: null }, now);
    expect(r.wrapped).toBe(false);
    expect(r.rebooted).toBe(true);
  });
});
