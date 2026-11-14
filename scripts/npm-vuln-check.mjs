#!/usr/bin/env node
// Runs `npm audit` in the given directory and fails on any advisory of
// high or critical severity that is not listed in
// .github/vuln-exceptions.json. Used by .github/workflows/security-audit.yml
// instead of relying on GitHub's Dependabot alerts alone: those read
// GitHub's dependency graph, which has been seen to sit weeks behind the
// lockfiles actually committed here, so alerts kept firing for versions
// already fixed while nothing audited the versions actually installed.
//
// Usage: node scripts/npm-vuln-check.mjs <dir> [--production]
//
// Moderate and low findings are printed but never fail the run; the
// exception list exists for high/critical advisories that are confirmed
// unreachable from this code and have no fixed release yet.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: npm-vuln-check.mjs <dir> [--production]");
  process.exit(2);
}
const production = process.argv.includes("--production");

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const exceptions = JSON.parse(readFileSync(join(repoRoot, ".github/vuln-exceptions.json"), "utf8"));
const npmExceptions = exceptions.npm ?? {};

// npm audit exits 1 whenever it finds anything, so the exit code says
// nothing about severity - the JSON report is what gets judged.
let report;
try {
  report = JSON.parse(
    execFileSync("npm", ["audit", "--json", ...(production ? ["--omit=dev"] : [])], {
      cwd: resolve(dir),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
      maxBuffer: 64 * 1024 * 1024,
    })
  );
} catch (err) {
  if (!err.stdout) throw err;
  report = JSON.parse(err.stdout);
}

// Each vulnerable package lists what makes it vulnerable in `via`: an
// advisory object for a direct finding, or a package name when it is
// only affected through a dependency. Only the objects carry an advisory.
const advisories = new Map();
for (const [pkg, vuln] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of vuln.via ?? []) {
    if (typeof via !== "object") continue;
    const id = via.url?.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? String(via.source);
    const entry = advisories.get(id) ?? { id, severity: via.severity, title: via.title, packages: new Set() };
    entry.packages.add(`${via.name ?? pkg}@${via.range ?? "?"}`);
    advisories.set(id, entry);
  }
}

const rank = { critical: 4, high: 3, moderate: 2, low: 1, info: 0 };
const sorted = [...advisories.values()].sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));

let failing = 0;
for (const a of sorted) {
  const blocking = (rank[a.severity] ?? 0) >= rank.high;
  const excepted = npmExceptions[a.id];
  const mark = !blocking ? "note" : excepted ? "excepted" : "FAIL";
  console.log(`${mark.padEnd(9)} ${a.severity.padEnd(8)} ${a.id}  ${a.title}  [${[...a.packages].join(", ")}]`);
  if (excepted) console.log(`          reason: ${excepted}`);
  if (blocking && !excepted) failing++;
}

// An exception that no longer matches anything is stale and should be
// removed, so it is called out rather than silently kept.
for (const id of Object.keys(npmExceptions)) {
  if (!advisories.has(id)) console.log(`stale     exception ${id} matches no current advisory - remove it`);
}

if (sorted.length === 0) console.log(`no advisories in ${dir}`);
console.log(`${failing} blocking advisor${failing === 1 ? "y" : "ies"} in ${dir}`);
process.exit(failing > 0 ? 1 : 0);
