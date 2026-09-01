import { XMLParser } from "fast-xml-parser";

// Parses nmap's own -oX output into the shape POST /api/ingest/hosts
// already accepts, so an imported scan lands through exactly the same
// path a scanner submission does (see ingestHostPayload).
//
// A real parser rather than regexes, deliberately: this is an uploaded
// file, so the input is attacker-influenceable, and nmap's own output
// already contains the awkward cases - a servicefp attribute carrying
// &quot;-escaped probe transcripts was right there in the very first real
// sample captured for these tests.

export interface ImportedPort {
  port: number;
  protocol: string;
  state: string;
  serviceName?: string;
  serviceProduct?: string;
  serviceVersion?: string;
  extraInfo?: string;
  osType?: string;
  cpes?: string[];
}

export interface ImportedHost {
  ip: string;
  hostname?: string;
  osName?: string;
  osFamily?: string;
  osVendor?: string;
  deviceType?: string;
  osAccuracy?: number;
  macAddress?: string;
  macVendor?: string;
  ports: ImportedPort[];
}

export interface ParsedNmapScan {
  hosts: ImportedHost[];
  // Reconstructed from <scaninfo>, in the U:/T: grammar masscan and nmap
  // share (see the UDP scanning section in CLAUDE.md). This becomes the
  // scan job's port_spec, which is what lets an import close ports the
  // same way a real scan does: the ingest path only concludes "closed"
  // for ports the job actually covered, so without this an import would
  // silently leave stale open ports behind.
  portSpec: string | null;
  // nmap's own argv, purely informational - shown back to whoever is
  // importing so they can confirm they picked the right file.
  args: string | null;
  // Hosts nmap saw as down. Not imported (there is nothing to record),
  // but counted so the import result can say so rather than looking like
  // it silently dropped them.
  hostsDown: number;
}

export class NmapXmlParseError extends Error {}

// Attributes come through prefixed so they can't collide with child
// element names - nmap has both a <hostname> element and name attributes.
const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@",
  // nmap emits repeated <host>, <port>, <cpe>... elements; without this a
  // single one parses as an object and a pair as an array, which is the
  // classic source of "works for two ports, crashes for one" bugs.
  isArray: (name) => ["host", "port", "hostname", "cpe", "osmatch", "osclass", "address", "scaninfo"].includes(name),
  processEntities: true,
});

function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

export function parseNmapXml(xml: string): ParsedNmapScan {
  let doc: any;
  try {
    doc = parser.parse(xml);
  } catch (err) {
    throw new NmapXmlParseError(`not valid XML: ${err instanceof Error ? err.message : String(err)}`);
  }

  const run = doc?.nmaprun;
  if (!run) throw new NmapXmlParseError("not an nmap XML report (no <nmaprun> element)");

  const hosts: ImportedHost[] = [];
  let hostsDown = 0;

  for (const host of asArray<any>(run.host)) {
    if (host?.status?.["@state"] === "down") {
      hostsDown += 1;
      continue;
    }

    const addresses = asArray<any>(host.address);
    // IPv4 and IPv6 are both accepted here - unlike a scan *target*,
    // where IPv6 has its own restricted path, an imported address is just
    // a value to record.
    const ipAddr = addresses.find((a) => a["@addrtype"] === "ipv4" || a["@addrtype"] === "ipv6");
    if (!ipAddr) continue;
    const mac = addresses.find((a) => a["@addrtype"] === "mac");

    // nmap can report several hostnames (PTR plus user-supplied); the PTR
    // one is what the scan pipeline itself records, so prefer it.
    const hostnames = asArray<any>(host.hostnames?.hostname);
    const hostname = (hostnames.find((h) => h["@type"] === "PTR") ?? hostnames[0])?.["@name"];

    const osmatches = asArray<any>(host.os?.osmatch);
    const bestOs = osmatches[0];
    const osclass = asArray<any>(bestOs?.osclass)[0];

    const ports: ImportedPort[] = [];
    for (const port of asArray<any>(host.ports?.port)) {
      const state = port.state?.["@state"];
      // Only what the scan actually found. "closed"/"filtered" ports are
      // deliberately dropped rather than submitted: the ingest path
      // derives closures itself from the job's port spec, and it does so
      // more carefully than a bare state string would (protocol-aware,
      // and only for ports the scan really covered).
      if (typeof state !== "string" || !state.startsWith("open")) continue;

      const portId = parseInt(port["@portid"], 10);
      if (Number.isNaN(portId) || portId < 1 || portId > 65535) continue;

      const service = port.service;
      const cpes = asArray<any>(service?.cpe)
        .map((c) => (typeof c === "string" ? c : c?.["#text"]))
        .filter((c: unknown): c is string => typeof c === "string" && c.length > 0);

      ports.push({
        port: portId,
        protocol: port["@protocol"] === "udp" ? "udp" : "tcp",
        // "open|filtered" (the normal UDP answer) is recorded as open:
        // it is the strongest statement nmap makes about an unanswered
        // UDP probe, and the scanner's own pipeline treats it the same.
        state: "open",
        serviceName: service?.["@name"],
        serviceProduct: service?.["@product"],
        serviceVersion: service?.["@version"],
        extraInfo: service?.["@extrainfo"],
        osType: service?.["@ostype"],
        cpes: cpes.length > 0 ? cpes : undefined,
      });
    }

    hosts.push({
      ip: String(ipAddr["@addr"]),
      hostname: hostname ? String(hostname) : undefined,
      osName: bestOs?.["@name"],
      osFamily: osclass?.["@osfamily"],
      osVendor: osclass?.["@vendor"],
      deviceType: osclass?.["@type"],
      osAccuracy: bestOs?.["@accuracy"] !== undefined ? parseInt(bestOs["@accuracy"], 10) : undefined,
      macAddress: mac?.["@addr"],
      macVendor: mac?.["@vendor"],
      ports,
    });
  }

  return {
    hosts,
    portSpec: buildPortSpec(asArray<any>(run.scaninfo)),
    args: run["@args"] ? String(run["@args"]) : null,
    hostsDown,
  };
}

// <scaninfo> carries the authoritative list of ports the run covered -
// far better than parsing it back out of the args string, and there is
// one element per scan type, so a combined TCP+UDP run produces two.
function buildPortSpec(scaninfos: any[]): string | null {
  const parts: string[] = [];
  for (const info of scaninfos) {
    const services = info?.["@services"];
    if (typeof services !== "string" || services.length === 0) continue;
    const udp = info["@protocol"] === "udp";
    for (const range of services.split(",")) {
      const trimmed = range.trim();
      if (!/^\d+(-\d+)?$/.test(trimmed)) continue;
      parts.push(udp ? `U:${trimmed}` : trimmed);
    }
  }
  return parts.length > 0 ? parts.join(",") : null;
}
