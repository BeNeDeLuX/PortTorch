/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Durable retry backlog for webhook/email alert deliveries. Until this
    -- existed, dispatch was strictly fire-and-forget: a target that was
    -- briefly unreachable lost the alert permanently, with only a failed
    -- webhook_deliveries row left behind. That's the weakest link in an
    -- alerting path - the scanner's own host submissions have had a
    -- durable retry queue (internal/submitqueue) for exactly this reason.
    --
    -- Deliberately its own table rather than more columns on
    -- webhook_deliveries: that one is a fixed-size diagnostic tail
    -- (trimmed to the most recent 50 per webhook at insert time), so a
    -- pending retry stored there could be trimmed away before it ever
    -- ran. This table holds only what is still owed and is emptied as it
    -- drains.
    CREATE TABLE webhook_retry_queue (
      id bigserial PRIMARY KEY,
      webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
      event text NOT NULL,
      message text NOT NULL,
      data jsonb NOT NULL DEFAULT '{}'::jsonb,
      attempt_count integer NOT NULL DEFAULT 1,
      next_attempt_at timestamptz NOT NULL,
      last_error text,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    -- The drainer's only query shape: due rows, oldest first.
    CREATE INDEX webhook_retry_queue_due_idx ON webhook_retry_queue (next_attempt_at);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`DROP TABLE IF EXISTS webhook_retry_queue;`);
};
