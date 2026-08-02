/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      ADD COLUMN pref_theme text CHECK (pref_theme IN ('dark', 'light')),
      ADD COLUMN pref_hosts_page_size integer CHECK (pref_hosts_page_size BETWEEN 1 AND 200),
      ADD COLUMN pref_show_active_scans_banner boolean NOT NULL DEFAULT true,
      ADD COLUMN pref_default_scanner_agent_id uuid REFERENCES scanner_agents(id) ON DELETE SET NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP COLUMN IF EXISTS pref_theme,
      DROP COLUMN IF EXISTS pref_hosts_page_size,
      DROP COLUMN IF EXISTS pref_show_active_scans_banner,
      DROP COLUMN IF EXISTS pref_default_scanner_agent_id;
  `);
};
