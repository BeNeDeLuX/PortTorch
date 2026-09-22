/* eslint-disable */
exports.shorthands = undefined;

// Three related gaps, one migration, because they are all about the same
// thing: the platform recorded what it found and never said how much of
// it to believe, nor shipped any of it to a SIEM.
//
// scan_jobs.discovered_hosts is what the scanner's discovery stage
// actually turned up, reported by the scanner because only it knows -
// the webserver sees only what survived enrichment. The gap between the
// two is the single most useful statement about a scan's quality: on a
// real deployment a nightly /24 reported 256 discovered and 5 confirmed,
// and nothing anywhere said so.
//
// scan_jobs.anomalies is computed webserver-side at completion, from what
// actually landed in the database rather than from the scanner's own
// tally - same reasoning as the completion counts beside it.
//
// The hec_* columns add two more forwarding streams. The existing two
// carry the audit trail and the scanners' own logs; the findings
// themselves - which ports opened, what nuclei matched - reached a SIEM
// only as fire-and-forget webhook posts, with no cursor and no backfill.
// Both new cursors follow the shape of the stream they page through:
// host_port_observations has a bigserial, so "everything after id N" is
// exact, while nuclei_findings is keyed by uuid and needs the same
// (timestamp, id) pair the scan-log cursor already uses.
//
// Both default to false. Turning on a stream that would replay months of
// history is an admin's decision, not a migration's.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_jobs
      ADD COLUMN discovered_hosts integer,
      ADD COLUMN anomalies jsonb
  `);
  pgm.sql(`
    ALTER TABLE hec_state
      ADD COLUMN observation_cursor bigint,
      ADD COLUMN finding_cursor_at timestamptz,
      ADD COLUMN finding_cursor_id uuid
  `);
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN hec_observations_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN hec_findings_enabled boolean NOT NULL DEFAULT false
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN hec_observations_enabled,
      DROP COLUMN hec_findings_enabled
  `);
  pgm.sql(`
    ALTER TABLE hec_state
      DROP COLUMN observation_cursor,
      DROP COLUMN finding_cursor_at,
      DROP COLUMN finding_cursor_id
  `);
  pgm.sql(`
    ALTER TABLE scan_jobs
      DROP COLUMN discovered_hosts,
      DROP COLUMN anomalies
  `);
};
