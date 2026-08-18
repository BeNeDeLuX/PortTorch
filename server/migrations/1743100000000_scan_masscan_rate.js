/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // Per-scan masscan packet rate override. Until now the rate was only
  // settable in the scanner's own config.yaml (masscanRate, default 1000),
  // so "scan this fragile/sensitive segment slowly" meant SSHing to the
  // scanner host, editing the file and restarting the service - and it
  // applied to every scan that scanner ran from then on, not just the one
  // that needed it.
  //
  // NULL means "use whatever the scanner's own config says", the same
  // absence-means-default idiom as scan_excludes.scanner_agent_id or
  // api_tokens.expires_at - so existing rows, and anyone who never sets
  // it, keep today's behavior exactly.
  //
  // Snapshotted onto scan_requests the same way nse_profile/nuclei_profile
  // already are (see the scan_profiles migration): scheduler.ts copies a
  // schedule's value onto each request it spawns rather than re-reading it
  // live, so editing a schedule can't retroactively change a request that
  // was already queued.
  pgm.sql(`
    ALTER TABLE scan_requests ADD COLUMN masscan_rate integer
      CHECK (masscan_rate IS NULL OR masscan_rate > 0);
    ALTER TABLE scan_schedules ADD COLUMN masscan_rate integer
      CHECK (masscan_rate IS NULL OR masscan_rate > 0);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_requests DROP COLUMN IF EXISTS masscan_rate;
    ALTER TABLE scan_schedules DROP COLUMN IF EXISTS masscan_rate;
  `);
};
