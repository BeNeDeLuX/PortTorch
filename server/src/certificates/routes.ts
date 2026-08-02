import { Router } from "express";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";

export const certificatesRouter = Router();
certificatesRouter.use(requireAuth);

// Fleet-wide view across all hosts, not just a single host's detail page -
// only the most recent certificate per host+port (same distinctOn pattern
// as the per-host query), sorted so the soonest-expiring certs surface
// first regardless of which host they belong to.
certificatesRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let query = db
    .selectFrom("tls_certificates")
    .innerJoin("hosts", "hosts.id", "tls_certificates.host_id")
    .select([
      "tls_certificates.id as id",
      "tls_certificates.host_id as host_id",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
      "tls_certificates.port as port",
      "tls_certificates.subject_cn as subject_cn",
      "tls_certificates.issuer_cn as issuer_cn",
      "tls_certificates.not_before as not_before",
      "tls_certificates.not_after as not_after",
      "tls_certificates.self_signed as self_signed",
      "tls_certificates.fingerprint_sha256 as fingerprint_sha256",
    ]);

  if (allowed) {
    query = query.where("hosts.scanner_agent_id", "in", allowed);
  }

  const certs = await query
    .distinctOn(["tls_certificates.host_id", "tls_certificates.port"])
    .orderBy("tls_certificates.host_id")
    .orderBy("tls_certificates.port")
    .orderBy("tls_certificates.captured_at", "desc")
    .execute();

  const sorted = certs.slice().sort((a, b) => {
    if (!a.not_after) return 1;
    if (!b.not_after) return -1;
    return new Date(a.not_after).getTime() - new Date(b.not_after).getTime();
  });

  res.json(sorted);
}));
