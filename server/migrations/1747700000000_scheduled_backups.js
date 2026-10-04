/* eslint-disable */
exports.shorthands = undefined;

// Scheduled backups to somewhere other than this host (backup/schedule.ts).
//
// A backup that only ever lands on the machine it protects is lost with
// that machine. The archive is the same one Settings -> Backup & Restore
// downloads and scripts/restore.sh reads; this only decides when it is
// made and where it goes.
//
// backup_target 'directory' writes to a path inside the container - a
// volume the operator mounts, typically an NFS or SMB share mounted on the
// host. 's3' uploads to any S3-compatible store. The secret key is
// withheld from the settings API like smtp_password.
//
// backup_last_* is the outcome of the last run, shown on the Settings page
// and Fleet Health, and backup_last_date makes the daily run happen once
// per day however often the ticker wakes up - the digest_email_state
// idiom.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN backup_schedule_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN backup_hour_utc integer NOT NULL DEFAULT 2 CHECK (backup_hour_utc BETWEEN 0 AND 23),
      ADD COLUMN backup_keep integer NOT NULL DEFAULT 7 CHECK (backup_keep BETWEEN 1 AND 365),
      ADD COLUMN backup_target text NOT NULL DEFAULT 'directory' CHECK (backup_target IN ('directory', 's3')),
      ADD COLUMN backup_directory text,
      ADD COLUMN backup_s3_endpoint text,
      ADD COLUMN backup_s3_region text NOT NULL DEFAULT 'us-east-1',
      ADD COLUMN backup_s3_bucket text,
      ADD COLUMN backup_s3_prefix text NOT NULL DEFAULT 'porttorch/',
      ADD COLUMN backup_s3_access_key text,
      ADD COLUMN backup_s3_secret_key text,
      ADD COLUMN backup_s3_path_style boolean NOT NULL DEFAULT true,
      ADD COLUMN backup_last_run_at timestamptz,
      ADD COLUMN backup_last_status text CHECK (backup_last_status IN ('succeeded', 'failed')),
      ADD COLUMN backup_last_error text,
      ADD COLUMN backup_last_location text,
      ADD COLUMN backup_last_bytes bigint,
      ADD COLUMN backup_last_success_at timestamptz,
      ADD COLUMN backup_last_date date;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN backup_last_date,
      DROP COLUMN backup_last_success_at,
      DROP COLUMN backup_last_bytes,
      DROP COLUMN backup_last_location,
      DROP COLUMN backup_last_error,
      DROP COLUMN backup_last_status,
      DROP COLUMN backup_last_run_at,
      DROP COLUMN backup_s3_path_style,
      DROP COLUMN backup_s3_secret_key,
      DROP COLUMN backup_s3_access_key,
      DROP COLUMN backup_s3_prefix,
      DROP COLUMN backup_s3_bucket,
      DROP COLUMN backup_s3_region,
      DROP COLUMN backup_s3_endpoint,
      DROP COLUMN backup_directory,
      DROP COLUMN backup_target,
      DROP COLUMN backup_keep,
      DROP COLUMN backup_hour_utc,
      DROP COLUMN backup_schedule_enabled;
  `);
};
