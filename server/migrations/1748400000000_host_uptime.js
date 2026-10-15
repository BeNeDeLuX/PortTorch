/* eslint-disable */
exports.shorthands = undefined;

// How long a device has been up, from the SNMP data every scan already
// collects (see src/lib/snmpUptime.ts). Stored as the boot time rather
// than an uptime, because a boot time stays true between scans while an
// uptime is stale the moment it is written - the dashboard computes "up
// for N days" from it at display time.
//
//   boot_time           when the device last started, as estimated from
//                       the newest reading (observation time - uptime)
//   uptime_source       'snmp-engine' (SNMPv3 engine time) or
//                       'snmp-sysuptime' (sysUpTime, wraps at 497 days)
//   uptime_observed_at  when that reading was taken
//   snmp_engine_boots   the SNMPv3 boot counter, which makes a reboot a
//                       fact rather than an inference (device.rebooted)
//
// Filled once from the SNMP output already stored, so devices show an
// uptime straight away rather than after their next scan. The parsing is
// a copy of src/lib/snmpUptime.ts's - migrations cannot import TypeScript.
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE hosts
      ADD COLUMN boot_time timestamptz,
      ADD COLUMN uptime_source text,
      ADD COLUMN uptime_observed_at timestamptz,
      ADD COLUMN snmp_engine_boots integer
  `);

  const duration = (text) => {
    const m = /^\s*(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?\s*$/.exec(text || "");
    if (!m || !text.trim() || m.slice(1).every((v) => v === undefined)) return null;
    return Number(m[1] || 0) * 86400 + Number(m[2] || 0) * 3600 + Number(m[3] || 0) * 60 + Number(m[4] || 0);
  };
  const { rows } = await pgm.db.query(`
    SELECT DISTINCT ON (o.host_id) o.host_id, o.observed_at, o.nse_extra
    FROM host_port_observations o
    WHERE o.nse_extra IS NOT NULL
      AND EXISTS (SELECT 1 FROM jsonb_array_elements(o.nse_extra) e WHERE e->>'id' IN ('snmp-info', 'snmp-sysdescr'))
    ORDER BY o.host_id, o.observed_at DESC
  `);
  for (const row of rows) {
    const scripts = row.nse_extra || [];
    let reading = null;
    const info = scripts.find((s) => s.id === "snmp-info");
    if (info) {
      const t = /snmpEngineTime:\s*([^\n]+)/.exec(info.output);
      const b = /snmpEngineBoots:\s*(\d+)/.exec(info.output);
      const secs = t ? duration(t[1]) : null;
      const boots = b ? Number(b[1]) : null;
      if (secs && secs > 0 && boots !== 0) reading = { secs, source: "snmp-engine", boots };
    }
    const sys = scripts.find((s) => s.id === "snmp-sysdescr");
    if (!reading && sys) {
      const ticks = /System uptime:[^\n]*\((\d+) timeticks\)/.exec(sys.output);
      if (ticks && Number(ticks[1]) > 0) reading = { secs: Number(ticks[1]) / 100, source: "snmp-sysuptime", boots: null };
    }
    if (!reading) continue;
    const observed = new Date(row.observed_at);
    await pgm.db.query(
      `UPDATE hosts SET boot_time = $2, uptime_source = $3, uptime_observed_at = $4, snmp_engine_boots = $5 WHERE id = $1`,
      [row.host_id, new Date(observed.getTime() - reading.secs * 1000), reading.source, observed, reading.boots]
    );
  }
};

exports.down = (pgm) => {
  pgm.sql(`ALTER TABLE hosts DROP COLUMN boot_time, DROP COLUMN uptime_source, DROP COLUMN uptime_observed_at, DROP COLUMN snmp_engine_boots`);
};
