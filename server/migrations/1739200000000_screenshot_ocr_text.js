/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE screenshots ADD COLUMN ocr_text text;
    ALTER TABLE rdp_screenshots ADD COLUMN ocr_text text;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE screenshots DROP COLUMN IF EXISTS ocr_text;
    ALTER TABLE rdp_screenshots DROP COLUMN IF EXISTS ocr_text;
  `);
};
