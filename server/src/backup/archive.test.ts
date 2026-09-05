import { describe, expect, it } from "vitest";
import { formatManifest, parseManifest, requiredFreeBytes } from "./archive";

// The manifest is the compatibility contract with scripts/backup.sh and
// restore.sh - both write and read this exact `key=value` shape, so a
// change here silently breaks restoring one tool's archive with the
// other. Pure string handling, no database or filesystem, same category
// as lib/cron.ts's own tests.
describe("backup manifest", () => {
  it("round-trips every field", () => {
    const manifest = {
      created_at: "2026-09-05T18:05:56Z",
      host: "b718066acf1a",
      checkout_version: "0.33.0",
      webserver_image: "unknown",
      git_commit: "unknown",
      schema_migration: "1745500000000_schedule_skip_when_pending",
      created_by: "admin",
      source: "dashboard",
    };
    expect(parseManifest(formatManifest(manifest))).toEqual(manifest);
  });

  it("reads a manifest written by scripts/backup.sh, which has no created_by/source", () => {
    const fromScript = [
      "created_at=2026-09-05T16:27:06Z",
      "host=porttorch-host",
      "checkout_version=0.32.0",
      "webserver_image=benedelux/porttorch-server:latest",
      "git_commit=6c3c010",
      "schema_migration=1745500000000_schedule_skip_when_pending",
      "",
    ].join("\n");
    const parsed = parseManifest(fromScript);
    expect(parsed.schema_migration).toBe("1745500000000_schedule_skip_when_pending");
    expect(parsed.git_commit).toBe("6c3c010");
    expect(parsed.created_by).toBeUndefined();
  });

  it("keeps a value containing '=' intact", () => {
    // Nothing writes one today, but splitting on every '=' rather than
    // the first would corrupt a value silently rather than loudly.
    expect(parseManifest("webserver_image=repo/img:tag=weird\n").webserver_image).toBe("repo/img:tag=weird");
  });

  it("ignores blank lines and anything without a key", () => {
    expect(parseManifest("\n\nhost=a\n=novalue\ngarbage\n")).toEqual({ host: "a" });
  });

  it("omits undefined fields rather than writing the string 'undefined'", () => {
    expect(formatManifest({ host: "a", git_commit: undefined })).toBe("host=a\n");
  });
});

describe("requiredFreeBytes", () => {
  it("asks for twice the data plus a flat floor", () => {
    // Staging holds db.sql.gz + data.tar.gz and then the archive
    // containing both, so roughly twice the size at peak.
    expect(requiredFreeBytes(0)).toBe(128 * 1024 * 1024);
    expect(requiredFreeBytes(1024)).toBe(2048 + 128 * 1024 * 1024);
  });
});
