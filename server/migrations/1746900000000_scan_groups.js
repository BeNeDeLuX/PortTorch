/* eslint-disable */
exports.shorthands = undefined;

// One scan split across several scanners. A group is the scan as it was
// requested - one target, one port spec - and each scanner gets its own
// scan_requests row carrying its share of the target. Those rows are
// ordinary queue entries in every other respect, so claiming, progress,
// cancelling and resuming all work per part with no changes of their own.
//
// The split itself is deterministic (lib/scanSplit.ts): the same address
// always goes to the same scanner. That is what keeps host identity -
// (ip, scanner_agent_id) - stable from one run to the next; a split that
// moved addresses between scanners would create a duplicate host row for
// every address that moved.
//
// scan_schedules.scanner_agent_ids is the schedule's full scanner set. The
// existing scanner_agent_id column stays and always holds the first of
// them, so its foreign key (ON DELETE CASCADE) and every reader written
// before this keep working unchanged. NULL means "just scanner_agent_id",
// which is what every existing schedule means.
//
// masscan_rate_split: the rate on the request is a total for the whole
// group and is divided between the parts, so splitting a scan cuts its
// runtime without multiplying the load on the target network.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scan_groups (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      target_spec text NOT NULL,
      port_spec text NOT NULL,
      parts integer NOT NULL,
      scanner_agent_ids uuid[] NOT NULL,
      masscan_rate_split boolean NOT NULL DEFAULT false,
      requested_by text,
      schedule_id uuid REFERENCES scan_schedules(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE scan_requests ADD COLUMN scan_group_id uuid REFERENCES scan_groups(id) ON DELETE SET NULL;
    ALTER TABLE scan_requests ADD COLUMN group_part integer;
    ALTER TABLE scan_requests ADD COLUMN group_parts integer;
    CREATE INDEX scan_requests_scan_group_id_idx ON scan_requests (scan_group_id) WHERE scan_group_id IS NOT NULL;

    ALTER TABLE scan_schedules ADD COLUMN scanner_agent_ids uuid[];
    ALTER TABLE scan_schedules ADD COLUMN masscan_rate_split boolean NOT NULL DEFAULT false;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_schedules DROP COLUMN IF EXISTS masscan_rate_split;
    ALTER TABLE scan_schedules DROP COLUMN IF EXISTS scanner_agent_ids;
    DROP INDEX IF EXISTS scan_requests_scan_group_id_idx;
    ALTER TABLE scan_requests DROP COLUMN IF EXISTS group_parts;
    ALTER TABLE scan_requests DROP COLUMN IF EXISTS group_part;
    ALTER TABLE scan_requests DROP COLUMN IF EXISTS scan_group_id;
    DROP TABLE IF EXISTS scan_groups;
  `);
};
