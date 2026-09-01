import { Router } from "express";
import multer from "multer";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { ingestHostPayload } from "../ingest/routes";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { NmapXmlParseError, parseNmapXml } from "./nmapXml";

export const importsRouter = Router();
importsRouter.use(requireAuth);

// 20 MB: a -oX of a large subnet with -sV and NSE output runs to a few
// megabytes, and the file is parsed in memory.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// Everything in this database exists because a PortTorch scanner found
// it, which leaves no way to bring in an nmap run from a network with no
// agent, or a historical scan predating the platform. This is that way in.
//
// Operator-level, like a rescan: it writes scan results, but it is a
// day-to-day action rather than configuration.
//
// The imported results go through ingestHostPayload - the *same* function
// POST /api/ingest/hosts uses - rather than their own insert path, so an
// import is indistinguishable from a scanner submission once it lands:
// same upsert semantics, same auto-tags, same host.new/port.opened/
// port.closed webhooks, same audit trail.
importsRouter.post(
  "/nmap",
  requireOperator,
  upload.single("file"),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: "an nmap XML file is required (multipart field \"file\")" });
      return;
    }

    // A scanner agent is required, not optional, because host identity is
    // (ip, scanner_agent_id): an unattributed host could not be told
    // apart from the same private address on a different scanner's
    // network. Picking one also decides which network these results are
    // understood to describe.
    const scannerAgentId = typeof req.body?.scannerAgentId === "string" ? req.body.scannerAgentId : "";
    const agent = await db
      .selectFrom("scanner_agents")
      .select(["id", "name"])
      .where("id", "=", scannerAgentId)
      .where("revoked_at", "is", null)
      .executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "scannerAgentId must name an active scanner agent" });
      return;
    }

    let scan;
    try {
      scan = parseNmapXml(req.file.buffer.toString("utf8"));
    } catch (err) {
      if (err instanceof NmapXmlParseError) {
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    }

    if (scan.hosts.length === 0) {
      res.status(400).json({
        error:
          scan.hostsDown > 0
            ? `no hosts with open ports in this file (${scan.hostsDown} host(s) were down)`
            : "no hosts with open ports in this file",
      });
      return;
    }

    // An explicit target spec wins over the addresses in the file. The
    // difference matters for Network Coverage: a /24 sweep that found
    // three hosts covered 256 addresses, not 3, and only the person doing
    // the import knows what was actually swept - nmap's args string is
    // not reliably parseable back into one.
    const providedTarget = typeof req.body?.targetSpec === "string" ? req.body.targetSpec.trim() : "";
    const targetSpec = providedTarget || scan.hosts.map((h) => h.ip).join(",");

    const job = await db
      .insertInto("scan_jobs")
      .values({
        scanner_agent_id: agent.id,
        target_spec: targetSpec,
        // From <scaninfo>, so the ingest path's port.closed detection
        // knows what this run actually covered. Falling back to the
        // discovered ports would be wrong in the one direction that
        // matters: it would make every port look covered and close
        // nothing.
        port_spec: scan.portSpec ?? "",
        status: "completed",
        cancellable: false,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();

    const result = await ingestHostPayload(
      { scanJobId: job.id, hosts: scan.hosts as never },
      { scannerAgentId: agent.id, scannerAgentName: agent.name, sourceIp: req.ip }
    );
    if (!result.ok) {
      res.status(result.status).json({ error: result.error });
      return;
    }

    const portCount = scan.hosts.reduce((sum, h) => sum + h.ports.length, 0);
    logger.info({
      event: "scan.imported",
      scan_job_id: job.id,
      scanner_agent_id: agent.id,
      scanner_agent_name: agent.name,
      hosts_imported: scan.hosts.length,
      open_ports_found: portCount,
      hosts_down: scan.hostsDown,
      target_spec: targetSpec,
      port_spec: scan.portSpec,
      nmap_args: scan.args,
      imported_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("scan.imported", req.session.username, req.ip, {
      scan_job_id: job.id,
      scanner_agent_name: agent.name,
      hosts_imported: scan.hosts.length,
      open_ports_found: portCount,
    });

    res.status(201).json({
      scanJobId: job.id,
      hostsImported: scan.hosts.length,
      openPortsFound: portCount,
      hostsDown: scan.hostsDown,
      targetSpec,
      portSpec: scan.portSpec,
      nmapArgs: scan.args,
    });
  })
);
