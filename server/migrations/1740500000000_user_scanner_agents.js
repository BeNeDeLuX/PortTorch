/* eslint-disable */
exports.shorthands = undefined;

// Restricts which scanner agents' results a non-admin dashboard user can
// see (server/src/auth/scannerScope.ts) - no rows for a user means
// unrestricted (today's behavior, unchanged), matching how scan_excludes
// treats a null scanner_agent_id as "applies to all" rather than "applies
// to none". Both FKs cascade: deleting the user or the scanner agent
// should just drop the now-meaningless assignment row, never block the
// delete itself.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE user_scanner_agents (
      user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, scanner_agent_id)
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS user_scanner_agents;
  `);
};
