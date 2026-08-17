import { describe, expect, it } from "vitest";
import { deriveServiceTags } from "./serviceTags";

describe("deriveServiceTags", () => {
  it("tags a port by service name", () => {
    expect(deriveServiceTags([{ port: 2222, protocol: "tcp", state: "open", serviceName: "ssh" }])).toEqual([
      "SSH-Server",
    ]);
  });

  it("falls back to the well-known port number when the service name doesn't say", () => {
    expect(deriveServiceTags([{ port: 22, protocol: "tcp", state: "open", serviceName: null }])).toEqual([
      "SSH-Server",
    ]);
  });

  it("matches every one of the requested example services", () => {
    expect(deriveServiceTags([{ port: 80, protocol: "tcp", state: "open", serviceName: "http" }])).toEqual([
      "WebServer",
    ]);
    expect(deriveServiceTags([{ port: 21, protocol: "tcp", state: "open", serviceName: "ftp" }])).toEqual([
      "FTP-Server",
    ]);
    expect(deriveServiceTags([{ port: 3389, protocol: "tcp", state: "open", serviceName: "ms-wbt-server" }])).toEqual(
      ["RDP"]
    );
  });

  it("ignores a closed/filtered port even if the service name would otherwise match", () => {
    expect(deriveServiceTags([{ port: 22, protocol: "tcp", state: "closed", serviceName: "ssh" }])).toEqual([]);
  });

  it("respects the protocol restriction on UDP-only rules", () => {
    expect(deriveServiceTags([{ port: 161, protocol: "tcp", state: "open", serviceName: null }])).toEqual([]);
    expect(deriveServiceTags([{ port: 161, protocol: "udp", state: "open", serviceName: null }])).toEqual(["SNMP"]);
  });

  it("returns one tag per matching service, deduplicated, in a multi-port host", () => {
    const tags = deriveServiceTags([
      { port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
      { port: 80, protocol: "tcp", state: "open", serviceName: "http" },
      { port: 443, protocol: "tcp", state: "open", serviceName: "https" },
      { port: 3306, protocol: "tcp", state: "open", serviceName: "mysql" },
    ]);
    expect(tags.sort()).toEqual(["MySQL", "SSH-Server", "WebServer"].sort());
  });

  it("returns nothing for a host with no recognizable services", () => {
    expect(deriveServiceTags([{ port: 12345, protocol: "tcp", state: "open", serviceName: "unknown" }])).toEqual([]);
  });
});
