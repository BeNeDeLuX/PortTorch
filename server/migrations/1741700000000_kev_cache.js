/* eslint-disable */
exports.shorthands = undefined;

// CISA's Known Exploited Vulnerabilities catalog - a third, independent
// vulnerability-priority signal alongside cve_cache's CVSS (severity) and
// epss_cache's EPSS (predicted exploitation probability): unlike EPSS,
// which estimates a probability, KEV membership means CISA has confirmed
// the CVE is *already* being actively exploited in the wild. Keyed by
// cve_id like epss_cache (KEV scores a specific vulnerability, not a
// product/version, so this isn't keyed by CPE the way cve_cache is).
//
// alert_sent_at mirrors epss_cache's own column and the same "fire once,
// never re-arm" reasoning - see kevSync.ts.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE kev_cache (
      cve_id text PRIMARY KEY,
      vendor_project text,
      product text,
      vulnerability_name text,
      date_added date,
      due_date date,
      known_ransomware_campaign_use text,
      synced_at timestamptz NOT NULL DEFAULT now(),
      alert_sent_at timestamptz
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS kev_cache;
  `);
};
