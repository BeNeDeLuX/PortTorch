/* eslint-disable */
exports.shorthands = undefined;

// Alert bundling: a scan that finds 40 new ports sent 40 messages, one per
// port, to every channel subscribed to port.opened - enough that people
// mute the channel, and a muted channel is worse than none. A channel with
// bundle_minutes > 0 instead collects its per-host events for that long
// (from the first one) and sends them as one message. 0, the default,
// keeps today's one-message-per-event behaviour for every existing channel.
// webhook_bundle_items is durable so a restart inside the window does not
// lose the alerts waiting in it.
//
// The weekly report: report.weekly, sent once a week (Monday, at the
// daily digest's hour) to every channel subscribed to it. weekly_report_state
// is the same singleton idiom as digest_email_state, recording the week it
// was last sent for so a restart within the hour cannot send it twice.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE webhooks ADD COLUMN bundle_minutes integer NOT NULL DEFAULT 0 CHECK (bundle_minutes BETWEEN 0 AND 60);

    CREATE TABLE webhook_bundle_items (
      id bigserial PRIMARY KEY,
      webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
      event text NOT NULL,
      message text NOT NULL,
      data jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX webhook_bundle_items_webhook_idx ON webhook_bundle_items (webhook_id, created_at);

    CREATE TABLE weekly_report_state (
      id integer PRIMARY KEY CHECK (id = 1),
      last_sent_week date
    );
    INSERT INTO weekly_report_state (id) VALUES (1);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE weekly_report_state;
    DROP TABLE webhook_bundle_items;
    ALTER TABLE webhooks DROP COLUMN bundle_minutes;
  `);
};
