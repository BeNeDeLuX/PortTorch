/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- One row per actual delivery attempt (webhook.ts's dispatchWebhook),
    -- for all three channel types - the only place an admin could
    -- previously see whether a webhook is actually working was the raw
    -- stdout logs (webhook.delivery_failed). Trimmed to the most recent
    -- rows per webhook at insert time (see operationalAlerts.ts-style
    -- capping elsewhere) rather than kept forever, since this is a
    -- diagnostic tail, not an audit trail like audit_log.
    CREATE TABLE webhook_deliveries (
      id bigserial PRIMARY KEY,
      webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
      event text NOT NULL,
      success boolean NOT NULL,
      status_code integer,
      error text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX webhook_deliveries_webhook_id_created_at_idx ON webhook_deliveries (webhook_id, created_at DESC);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS webhook_deliveries;
  `);
};
