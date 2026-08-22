/* eslint-disable */
exports.shorthands = undefined;

// The last three alerting tunables that still needed a redeploy to
// change. The digest hour is the one that made the split obvious: after
// SMTP moved into app_settings, *what* PortTorch mails with was
// configurable from the dashboard while *when* the daily digest goes out
// still lived in .env - one feature, two places, one of them requiring a
// container restart.
//
// Seeded once from the current env values so an existing deployment's
// tuning carries over; from here on config.ts no longer has these fields
// and the consumers read app_settings.
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE app_settings
      ADD COLUMN digest_email_hour_utc integer NOT NULL DEFAULT 8,
      ADD COLUMN epss_alert_threshold double precision NOT NULL DEFAULT 0.5,
      ADD COLUMN queue_backlog_threshold_minutes integer NOT NULL DEFAULT 30
  `);

  const hour = parseInt(process.env.DIGEST_EMAIL_HOUR_UTC ?? "8", 10);
  const epss = parseFloat(process.env.EPSS_ALERT_THRESHOLD ?? "0.5");
  const backlog = parseInt(process.env.QUEUE_BACKLOG_THRESHOLD_MINUTES ?? "30", 10);

  await pgm.db.query(
    `UPDATE app_settings
        SET digest_email_hour_utc = $1,
            epss_alert_threshold = $2,
            queue_backlog_threshold_minutes = $3
      WHERE id = 1`,
    [
      Number.isFinite(hour) && hour >= 0 && hour <= 23 ? hour : 8,
      Number.isFinite(epss) && epss >= 0 && epss <= 1 ? epss : 0.5,
      Number.isFinite(backlog) && backlog >= 1 ? backlog : 30,
    ]
  );
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN IF EXISTS digest_email_hour_utc,
      DROP COLUMN IF EXISTS epss_alert_threshold,
      DROP COLUMN IF EXISTS queue_backlog_threshold_minutes;
  `);
};
