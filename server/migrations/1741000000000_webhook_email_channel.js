/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE webhooks
      ADD COLUMN channel_type text NOT NULL DEFAULT 'webhook' CHECK (channel_type IN ('webhook', 'email')),
      ADD COLUMN email_to text,
      ALTER COLUMN url DROP NOT NULL;

    ALTER TABLE webhooks
      ADD CONSTRAINT webhooks_channel_type_fields_check CHECK (
        (channel_type = 'webhook' AND url IS NOT NULL AND email_to IS NULL)
        OR
        (channel_type = 'email' AND email_to IS NOT NULL AND url IS NULL)
      );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM webhooks WHERE channel_type = 'email';
    ALTER TABLE webhooks
      DROP CONSTRAINT webhooks_channel_type_fields_check,
      DROP COLUMN channel_type,
      DROP COLUMN email_to,
      ALTER COLUMN url SET NOT NULL;
  `);
};
