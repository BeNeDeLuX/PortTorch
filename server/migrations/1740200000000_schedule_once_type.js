/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_schedules
      DROP CONSTRAINT scan_schedules_schedule_type_check,
      ADD CONSTRAINT scan_schedules_schedule_type_check CHECK (schedule_type IN ('interval', 'cron', 'once')),
      ADD COLUMN run_at timestamptz;

    ALTER TABLE scan_schedules
      DROP CONSTRAINT scan_schedules_type_fields_check,
      ADD CONSTRAINT scan_schedules_type_fields_check CHECK (
        (schedule_type = 'interval' AND interval_minutes IS NOT NULL AND cron_expression IS NULL AND run_at IS NULL)
        OR
        (schedule_type = 'cron' AND cron_expression IS NOT NULL AND interval_minutes IS NULL AND run_at IS NULL)
        OR
        (schedule_type = 'once' AND run_at IS NOT NULL AND interval_minutes IS NULL AND cron_expression IS NULL)
      );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM scan_schedules WHERE schedule_type = 'once';
    ALTER TABLE scan_schedules
      DROP CONSTRAINT scan_schedules_type_fields_check,
      ADD CONSTRAINT scan_schedules_type_fields_check CHECK (
        (schedule_type = 'interval' AND interval_minutes IS NOT NULL AND cron_expression IS NULL)
        OR
        (schedule_type = 'cron' AND cron_expression IS NOT NULL AND interval_minutes IS NULL)
      );

    ALTER TABLE scan_schedules
      DROP CONSTRAINT scan_schedules_schedule_type_check,
      ADD CONSTRAINT scan_schedules_schedule_type_check CHECK (schedule_type IN ('interval', 'cron')),
      DROP COLUMN run_at;
  `);
};
