#!/usr/bin/env node
// Runs govulncheck over the scanner module and fails on any vulnerability
// whose affected function this code actually calls, unless it is listed
// in .github/vuln-exceptions.json. Counterpart of npm-vuln-check.mjs for
// the Go half; see that file for why the repo audits itself instead of
// trusting Dependabot's view of the dependency graph.
//
// Usage: node scripts/go-vuln-check.mjs <module dir>
//
// govulncheck tells "called" from "merely imported" apart: a finding whose
// trace reaches a function is on a real call path, one that stops at the
// module or package is a dependency carrying the vulnerable code without
// this program reaching it. Only the called kind blocks, which is also
// what govulncheck's own text mode fails on. Imported-only findings are
// printed so a reviewer sees them, same as moderate npm findings.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: go-vuln-check.mjs <module dir>");
  process.exit(2);
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const exceptions = JSON.parse(readFileSync(join(repoRoot, ".github/vuln-exceptions.json"), "utf8"));
const goExceptions = exceptions.go ?? {};

const run = spawnSync("govulncheck", ["-format", "json", "./..."], {
  cwd: resolve(dir),
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
  maxBuffer: 64 * 1024 * 1024,
});
if (run.error) throw run.error;
// In JSON mode govulncheck exits 0 even with findings; a non-zero exit is
// a tool failure (no network, broken module), not a verdict.
if (run.status !== 0) {
  console.error(`govulncheck exited with ${run.status}`);
  process.exit(2);
}

// The output is a stream of JSON objects, one per line group, each with a
// single key: config, progress, osv (advisory details) or finding.
const osv = new Map();
const findings = [];
for (const chunk of run.stdout.split(/^(?=\{)/m)) {
  const text = chunk.trim();
  if (!text) continue;
  const obj = JSON.parse(text);
  if (obj.osv) osv.set(obj.osv.id, obj.osv);
  if (obj.finding) findings.push(obj.finding);
}

// One vulnerability yields several findings (one per call path, plus
// coarser package- and module-level ones); keep the most specific level.
const byId = new Map();
for (const f of findings) {
  const called = f.trace?.some((t) => t.function);
  const entry = byId.get(f.osv) ?? { id: f.osv, called: false, fixed: f.fixed_version, module: f.trace?.at(-1)?.module };
  entry.called ||= Boolean(called);
  byId.set(f.osv, entry);
}

let failing = 0;
const sorted = [...byId.values()].sort((a, b) => Number(b.called) - Number(a.called));
for (const v of sorted) {
  const summary = osv.get(v.id)?.summary ?? "";
  const alias = osv.get(v.id)?.aliases?.find((a) => a.startsWith("GHSA-")) ?? "";
  const excepted = goExceptions[v.id];
  const mark = !v.called ? "imported" : excepted ? "excepted" : "FAIL";
  console.log(
    `${mark.padEnd(9)} ${v.id}${alias ? ` (${alias})` : ""}  ${summary}  [${v.module ?? "?"}, fixed in ${v.fixed ?? "no release"}]`
  );
  if (excepted) console.log(`          reason: ${excepted}`);
  if (v.called && !excepted) failing++;
}

for (const id of Object.keys(goExceptions)) {
  if (!byId.has(id)) console.log(`stale     exception ${id} matches no current finding - remove it`);
}

if (sorted.length === 0) console.log(`no vulnerabilities in ${dir}`);
console.log(`${failing} called vulnerabilit${failing === 1 ? "y" : "ies"} in ${dir}`);
process.exit(failing > 0 ? 1 : 0);
