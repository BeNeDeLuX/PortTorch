import { describe, expect, it } from "vitest";
import { AUTO_TAG_NAMES, isAutoTag } from "./knownServiceTags";

describe("isAutoTag", () => {
  it("recognizes a service tag the ingest path can add automatically", () => {
    expect(isAutoTag("WebServer")).toBe(true);
    expect(isAutoTag("SSH-Server")).toBe(true);
    expect(isAutoTag("Docker-API")).toBe(true);
  });

  it("treats an arbitrary user-typed tag as manual", () => {
    expect(isAutoTag("owner:jane")).toBe(false);
    expect(isAutoTag("prod")).toBe(false);
  });

  it("matches exactly, not case-insensitively - these names are generated, never typed", () => {
    expect(isAutoTag("webserver")).toBe(false);
    expect(isAutoTag("WEBSERVER")).toBe(false);
  });

  // Guards the one way this frontend-only copy can silently rot: someone
  // adds a rule to server/src/lib/serviceTags.ts and forgets this list,
  // so the new tag renders as if a human had typed it. A count check
  // can't catch that on its own, but it does force a deliberate edit here.
  it("covers every service tag the backend's rule table currently produces", () => {
    expect(AUTO_TAG_NAMES.size).toBe(18);
    expect([...AUTO_TAG_NAMES].sort()).toEqual(
      [
        "DNS-Server",
        "Docker-API",
        "FTP-Server",
        "IPMI",
        "LDAP",
        "MSSQL",
        "Mail-Server",
        "MongoDB",
        "MySQL",
        "PostgreSQL",
        "RDP",
        "Redis",
        "SMB",
        "SNMP",
        "SSH-Server",
        "Telnet",
        "VNC",
        "WebServer",
      ].sort()
    );
  });
});
