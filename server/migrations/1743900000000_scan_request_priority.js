/**
 * Scan queue priority.
 *
 * Until now the scanner's claim query was strictly FIFO (ORDER BY
 * created_at), so an ad-hoc scan an operator is actively waiting for sat
 * behind whatever large scheduled sweep happened to be queued first -
 * and, because a "serve" scanner's polling loop blocks for the whole
 * duration of the scan it's running, potentially for hours.
 *
 * Text rather than an ordinal integer, matching nse_profile/nuclei_profile
 * and every other small enum here; see src/scanPriority.ts for why the
 * ordering cost that implies doesn't matter at this table's size.
 *
 * scan_schedules gets the same column, snapshotted onto each request the
 * scheduler spawns - identical semantics to the nse_/nuclei_ profile
 * snapshot columns it already copies.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE scan_requests
      ADD COLUMN priority text NOT NULL DEFAULT 'normal'
      CHECK (priority IN ('high', 'normal', 'low'))
  `);
  await pgm.db.query(`
    ALTER TABLE scan_schedules
      ADD COLUMN priority text NOT NULL DEFAULT 'normal'
      CHECK (priority IN ('high', 'normal', 'low'))
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE scan_schedules DROP COLUMN priority`);
  await pgm.db.query(`ALTER TABLE scan_requests DROP COLUMN priority`);
};
