/* eslint-disable */
exports.shorthands = undefined;

// The outbound proxy was configurable only through HTTP_PROXY/HTTPS_PROXY/
// NO_PROXY in .env, which meant a redeploy to change it - and a proxy is
// the first thing that is wrong in a new network, so that is the setting
// you least want to need a container restart for.
//
// Deliberately NOT seeded from the environment, unlike the tunables that
// moved here before it. Those had exactly one consumer each, so copying
// the value and never reading the variable again was a clean cut. Here
// the environment keeps mattering: `lib/proxy.ts` falls back to it
// whenever these columns are empty, so an existing deployment that sets
// HTTP_PROXY in .env keeps working untouched, and an admin who fills
// these in takes over from that point on. Seeding would have made the
// dashboard show a value the operator never typed, and left .env looking
// authoritative when it no longer was.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN proxy_http_url text,
      ADD COLUMN proxy_https_url text,
      ADD COLUMN proxy_no_proxy text
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN proxy_http_url,
      DROP COLUMN proxy_https_url,
      DROP COLUMN proxy_no_proxy
  `);
};
