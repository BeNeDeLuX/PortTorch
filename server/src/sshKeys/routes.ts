import { Router } from "express";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { limitFindings } from "../lib/findingLimit";

export const sshKeysRouter = Router();
sshKeysRouter.use(requireAuth);

// Fleet-wide view of every SSH host key, the counterpart to the
// certificates router above it - same "most recent per identity" shape
// (distinctOn, newest captured_at wins), identity here being
// (host, port, key_type) exactly as the host detail page's own query uses.
//
// What this page exists for that host detail can't show: the same host key
// appearing on more than one address. A host key is supposed to be unique
// per machine, so a repeated fingerprint means a cloned VM/image, a golden
// image that shipped its keys, or a genuinely shared private key - none of
// which are visible while looking at one host at a time.
sshKeysRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let query = db
    .selectFrom("ssh_host_keys")
    .innerJoin("hosts", "hosts.id", "ssh_host_keys.host_id")
    .select([
      "ssh_host_keys.id as id",
      "ssh_host_keys.host_id as host_id",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
      "ssh_host_keys.port as port",
      "ssh_host_keys.key_type as key_type",
      "ssh_host_keys.bits as bits",
      "ssh_host_keys.fingerprint_sha256 as fingerprint_sha256",
      "ssh_host_keys.fingerprint_md5 as fingerprint_md5",
      "ssh_host_keys.captured_at as captured_at",
    ]);

  if (allowed) {
    query = query.where("hosts.scanner_agent_id", "in", allowed);
  }

  const keys = await query
    .distinctOn(["ssh_host_keys.host_id", "ssh_host_keys.port", "ssh_host_keys.key_type"])
    .orderBy("ssh_host_keys.host_id")
    .orderBy("ssh_host_keys.port")
    .orderBy("ssh_host_keys.key_type")
    .orderBy("ssh_host_keys.captured_at", "desc")
    .execute();

  // Sharing is counted in distinct *addresses*, not distinct hosts rows,
  // and deliberately so: host identity is (ip, scanner_agent_id) (see the
  // hostIdentity integration test), so one physical machine reachable from
  // two scanners is two hosts rows legitimately serving the same key -
  // counting rows would report that as "shared" every time. Counting
  // addresses means a group only ever flags when the key really did turn
  // up at more than one address.
  //
  // Grouping runs over the scanner-scoped result set above rather than the
  // whole table, so a user restricted to one scanner never gets a count
  // that includes hosts they can't open.
  const ipsByFingerprint = new Map<string, Set<string>>();
  for (const k of keys) {
    if (!k.fingerprint_sha256) continue;
    const ips = ipsByFingerprint.get(k.fingerprint_sha256) ?? new Set<string>();
    ips.add(String(k.host_ip));
    ipsByFingerprint.set(k.fingerprint_sha256, ips);
  }

  const rows = keys.map((k) => ({
    ...k,
    shared_ip_count: k.fingerprint_sha256 ? (ipsByFingerprint.get(k.fingerprint_sha256)?.size ?? 1) : 1,
  }));

  // Shared keys first (most-shared first), since that's the finding this
  // page exists to surface; ties fall back to host/port for a stable order.
  rows.sort((a, b) => {
    if (a.shared_ip_count !== b.shared_ip_count) return b.shared_ip_count - a.shared_ip_count;
    const ip = String(a.host_ip).localeCompare(String(b.host_ip));
    return ip !== 0 ? ip : a.port - b.port;
  });

  res.json(limitFindings(rows));
}));
