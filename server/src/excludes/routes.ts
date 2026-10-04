import { Router } from "express";
import net from "net";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { isIPv4, isIPv4Cidr, isIPv4Range, isIPv6, isIPv6Cidr } from "../lib/net";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { countExcludePattern, expandExcludePattern, parseExcludePatternValue } from "../lib/targetPattern";

// Admin-only, like scanner agents/schedules/webhooks - this controls what
// every scanner instance is allowed to scan at all, not a day-to-day host
// action.
export const excludesRouter = Router();
excludesRouter.use(requireAuth, requireAdmin);

const uuidSchema = z.string().uuid();

function isValidPortSpec(value: string): boolean {
  const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(value);
  if (!match) return false;
  const lo = Number(match[1]);
  const hi = match[2] !== undefined ? Number(match[2]) : lo;
  return lo >= 1 && hi <= 65535 && lo <= hi;
}

// "ip:portSpec", e.g. "10.0.0.5:3389" or "10.0.0.5:8000-8010" - unlike
// plain "ip" excludes, only a single address is allowed here (not a
// CIDR/range), since the scanner enforces this one by filtering the
// discovery results for that exact IP (see scanner's pipeline/excludes.go
// filterIPPortExcludes) rather than by ever telling masscan/nmap to skip
// it. An IPv6 address needs bracket notation, "[ipv6]:portSpec" (e.g.
// "[2001:db8::1]:3389") - unlike IPv4, an IPv6 address itself contains
// colons, so there's no other unambiguous way to split "address" from
// "port" out of one text value. ingest/routes.ts's GET /excludes handler
// (which reconstructs {ip, portSpec} for the scanner) needs the same
// bracket-aware split.
function isValidIPPortValue(value: string): boolean {
  if (value.startsWith("[")) {
    const closeIdx = value.indexOf("]:");
    if (closeIdx === -1) return false;
    return isIPv6(value.slice(1, closeIdx)) && isValidPortSpec(value.slice(closeIdx + 2));
  }
  const idx = value.indexOf(":");
  if (idx === -1) return false;
  return isIPv4(value.slice(0, idx)) && isValidPortSpec(value.slice(idx + 1));
}

excludesRouter.get("/", asyncHandler(async (_req, res) => {
  const excludes = await db
    .selectFrom("scan_excludes")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_excludes.scanner_agent_id")
    .select([
      "scan_excludes.id as id",
      "scan_excludes.kind as kind",
      "scan_excludes.value as value",
      "scan_excludes.scanner_agent_id as scanner_agent_id",
      "scanner_agents.name as scanner_agent_name",
      "scan_excludes.created_by as created_by",
      "scan_excludes.created_at as created_at",
    ])
    .orderBy("scan_excludes.kind")
    .orderBy("scan_excludes.created_at")
    .execute();
  // How many addresses a pattern exclude actually covers, so "*.2 in
  // 10.46.0.0/16" reads as the 256 addresses it is rather than as one rule.
  res.json(excludes.map((e) => (e.kind === "ip_pattern" ? { ...e, address_count: countExcludePattern(e.value) } : e)));
}));

// What a pattern exclude would cover, before it is saved - so a typo in
// the range or the pattern shows up while typing, as a count and the first
// few addresses, rather than as a rule that quietly excludes the wrong
// thing (or nothing) from every scan. Same parser and expansion the saved
// rule and the scanner-facing exclude list use, so the preview cannot
// disagree with what will actually be excluded.
excludesRouter.get("/pattern-preview", asyncHandler(async (req, res) => {
  const value = typeof req.query.value === "string" ? req.query.value : "";
  const parsed = parseExcludePatternValue(value);
  if ("error" in parsed) {
    res.json({ ok: false, error: parsed.error });
    return;
  }
  const entries = expandExcludePattern(value);
  res.json({ ok: true, addressCount: countExcludePattern(value), sample: entries.slice(0, 5), entries: entries.length });
}));

const createExcludeSchema = z.object({
  // ip_pattern: "<range> <pattern>", e.g. "10.46.0.0/16 *.2" - every
  // address in the range matching the pattern (lib/targetPattern.ts).
  kind: z.enum(["ip", "port", "ip_port", "ip_pattern"]),
  value: z.string().trim().min(1).max(64),
  // Omitted/null = applies to every scanner (the inherited default).
  scannerAgentId: z.string().uuid().nullish(),
});

excludesRouter.post("/", asyncHandler(async (req, res) => {
  const parsed = createExcludeSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { kind } = parsed.data;
  let { value } = parsed.data;
  const scannerAgentId = parsed.data.scannerAgentId ?? null;

  if (kind === "ip_pattern") {
    const pattern = parseExcludePatternValue(value);
    if ("error" in pattern) {
      res.status(400).json({ error: pattern.error });
      return;
    }
    // One canonical spacing, so the duplicate check below catches the same
    // rule typed with two spaces instead of one.
    value = `${pattern.scopeText} ${pattern.patternText}`;
  }

  // A pattern was already validated above. Parenthesised deliberately: a
  // bare `kind === "ip_pattern" || kind === "ip" ? ... : ...` reads as
  // `(... || ...) ? ...`, which ran a pattern through the IP check and
  // rejected every one - caught by the integration test.
  const isValid =
    kind === "ip_pattern" ||
    (kind === "ip"
      ? net.isIP(value) === 4 || isIPv4Cidr(value) || isIPv4Range(value) || isIPv6(value) || isIPv6Cidr(value)
      : kind === "port"
        ? isValidPortSpec(value)
        : isValidIPPortValue(value));
  if (!isValid) {
    res.status(400).json({
      error:
        kind === "ip"
          ? "value must be a single IPv4 address, an IPv4 CIDR/address range (e.g. 10.0.0.1-10.0.0.10), a single IPv6 address, or an IPv6 CIDR (e.g. 2001:db8::/32)"
          : kind === "port"
            ? "value must be a port (1-65535) or a range like 8000-8010"
            : "value must be ip:port or ip:portRange (e.g. 10.0.0.5:3389 or 10.0.0.5:8000-8010), or [ipv6]:port for IPv6 (e.g. [2001:db8::1]:3389)",
    });
    return;
  }

  let scannerAgentName: string | null = null;
  if (scannerAgentId) {
    const agent = await db.selectFrom("scanner_agents").select(["id", "name"]).where("id", "=", scannerAgentId).executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "scanner agent not found" });
      return;
    }
    scannerAgentName = agent.name;
  }

  // Application-level duplicate check rather than a DB-level onConflict:
  // the two partial unique indexes (global vs. per-scanner) can't both be
  // targeted by a single onConflict clause, and this NULL-safe comparison
  // (IS NOT DISTINCT FROM) is simpler than picking the right index at
  // query-build time.
  const existing = await db
    .selectFrom("scan_excludes")
    .select(["id"])
    .where("kind", "=", kind)
    .where("value", "=", value)
    .where((eb) =>
      scannerAgentId ? eb("scanner_agent_id", "=", scannerAgentId) : eb("scanner_agent_id", "is", null)
    )
    .executeTakeFirst();
  if (existing) {
    res.status(409).json({ error: "this exclude already exists" });
    return;
  }

  const exclude = await db
    .insertInto("scan_excludes")
    .values({ kind, value, scanner_agent_id: scannerAgentId, created_by: req.session.username! })
    .returning(["id", "kind", "value", "scanner_agent_id", "created_by", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "exclude.created",
    exclude_id: exclude.id,
    kind,
    value,
    scanner_agent_id: scannerAgentId,
    scanner_agent_name: scannerAgentName,
    created_by: req.session.username,
  });
  recordAudit("exclude.created", req.session.username, req.ip, {
    exclude_id: exclude.id,
    kind,
    value,
    scanner_agent_id: scannerAgentId,
    scanner_agent_name: scannerAgentName,
  });

  res.status(201).json(exclude);
}));

excludesRouter.delete("/:id", asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid exclude id" });
    return;
  }

  const result = await db.deleteFrom("scan_excludes").where("id", "=", req.params.id).executeTakeFirst();
  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "exclude not found" });
    return;
  }

  logger.info({ event: "exclude.deleted", exclude_id: req.params.id, deleted_by: req.session.username });
  recordAudit("exclude.deleted", req.session.username, req.ip, { exclude_id: req.params.id });

  res.status(204).end();
}));
