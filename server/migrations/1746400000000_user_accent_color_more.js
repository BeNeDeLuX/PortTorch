/* eslint-disable */
exports.shorthands = undefined;

// Three more accent colours: lila, pink, and one taken from Vim's own
// `evening` colorscheme. Same shape as the migration that added blue -
// the constraint is the database's copy of the list that also lives in
// frontend/src/lib/accent.ts (ACCENT_COLORS) and auth/routes.ts's zod
// enum, and all three have to move together.
//
// The down migration can strip the new values from the constraint but
// would leave any row already holding one, which the constraint then
// rejects on its next update - so it clears those back to NULL (the
// default orange) first. Losing a colour preference on a rollback is the
// harmless half of that trade.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP CONSTRAINT users_pref_accent_color_check,
      ADD CONSTRAINT users_pref_accent_color_check
        CHECK (pref_accent_color IN ('green', 'orange', 'blue', 'lila', 'pink', 'evening'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    UPDATE users SET pref_accent_color = NULL
     WHERE pref_accent_color IN ('lila', 'pink', 'evening');
    ALTER TABLE users
      DROP CONSTRAINT users_pref_accent_color_check,
      ADD CONSTRAINT users_pref_accent_color_check
        CHECK (pref_accent_color IN ('green', 'orange', 'blue'));
  `);
};
