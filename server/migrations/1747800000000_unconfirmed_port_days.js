/* eslint-disable */
exports.shorthands = undefined;

// How long an open port may go without being re-confirmed before it is
// flagged "unconfirmed" (search/routes.ts, scanStats, Host Detail).
//
// It used to mean "older than this host's newest observation", i.e. not
// part of the most recent scan's results. That was the right signal before
// a covered-but-absent port was recorded closed by ingest; since then the
// only open ports a newer scan leaves behind are ones it never asked about,
// so every targeted single-port scan flagged all the other ports of the
// host - the opposite of useful. Age is the signal left: a port nobody has
// confirmed in this many days, whatever scans ran in between.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN unconfirmed_port_days integer NOT NULL DEFAULT 30 CHECK (unconfirmed_port_days BETWEEN 1 AND 3650);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`ALTER TABLE app_settings DROP COLUMN unconfirmed_port_days;`);
};
