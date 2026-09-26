/* eslint-disable */
exports.shorthands = undefined;

// How wide a page may get, for the workstations the 1600px cap was never
// written for - 32" and ultrawide/curved monitors, where the standard
// layout leaves most of the screen empty.
//
// Nullable with no default, like every other pref_* column: NULL means
// "never chosen", which is what lets the frontend tell that apart from a
// deliberate "standard" and seed only a browser that has never had a
// choice made on it. The live value is per browser (localStorage); this
// column is what follows the account to a new one.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      ADD COLUMN pref_layout_width text
        CHECK (pref_layout_width IN ('standard', 'wide'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP COLUMN IF EXISTS pref_layout_width;
  `);
};
