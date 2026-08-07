import { z } from "zod";

// zod v3's z.string().ip() accepted either an IPv4 or an IPv6 address with
// no way to restrict it further than that; v4 split it into separate
// z.ipv4()/z.ipv6() schemas with no combined replacement, so this union
// reproduces the old "either family" behavior in the one place it's
// actually needed - the ip/hostIp fields ingest/routes.ts and
// integrations/routes.ts accept, both of which are genuinely dual-stack
// (see hosts.ip being Postgres inet, and the scanner's own IPv6 target
// support).
export function zIp() {
  return z.union([z.ipv4(), z.ipv6()]);
}
