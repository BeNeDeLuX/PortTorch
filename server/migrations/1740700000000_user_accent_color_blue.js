/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP CONSTRAINT users_pref_accent_color_check,
      ADD CONSTRAINT users_pref_accent_color_check CHECK (pref_accent_color IN ('green', 'orange', 'blue'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP CONSTRAINT users_pref_accent_color_check,
      ADD CONSTRAINT users_pref_accent_color_check CHECK (pref_accent_color IN ('green', 'orange'));
  `);
};
