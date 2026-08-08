/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE webhooks
      DROP CONSTRAINT webhooks_channel_type_check,
      ADD CONSTRAINT webhooks_channel_type_check CHECK (channel_type IN ('webhook', 'email', 'teams'));

    ALTER TABLE webhooks
      DROP CONSTRAINT webhooks_channel_type_fields_check,
      ADD CONSTRAINT webhooks_channel_type_fields_check CHECK (
        (channel_type IN ('webhook', 'teams') AND url IS NOT NULL AND email_to IS NULL)
        OR
        (channel_type = 'email' AND email_to IS NOT NULL AND url IS NULL)
      );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM webhooks WHERE channel_type = 'teams';
    ALTER TABLE webhooks
      DROP CONSTRAINT webhooks_channel_type_fields_check,
      ADD CONSTRAINT webhooks_channel_type_fields_check CHECK (
        (channel_type = 'webhook' AND url IS NOT NULL AND email_to IS NULL)
        OR
        (channel_type = 'email' AND email_to IS NOT NULL AND url IS NULL)
      );

    ALTER TABLE webhooks
      DROP CONSTRAINT webhooks_channel_type_check,
      ADD CONSTRAINT webhooks_channel_type_check CHECK (channel_type IN ('webhook', 'email'));
  `);
};
