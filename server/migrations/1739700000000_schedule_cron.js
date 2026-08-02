/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_schedules
      ADD COLUMN schedule_type text NOT NULL DEFAULT 'interval' CHECK (schedule_type IN ('interval', 'cron')),
      ADD COLUMN cron_expression text,
      ALTER COLUMN interval_minutes DROP NOT NULL;

    ALTER TABLE scan_schedules
      ADD CONSTRAINT scan_schedules_type_fields_check CHECK (
        (schedule_type = 'interval' AND interval_minutes IS NOT NULL AND cron_expression IS NULL)
        OR
        (schedule_type = 'cron' AND cron_expression IS NOT NULL AND interval_minutes IS NULL)
      );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM scan_schedules WHERE schedule_type = 'cron';
    ALTER TABLE scan_schedules
      DROP CONSTRAINT scan_schedules_type_fields_check,
      DROP COLUMN schedule_type,
      DROP COLUMN cron_expression,
      ALTER COLUMN interval_minutes SET NOT NULL;
  `);
};
