import { describe, expect, it } from "vitest";
import { parseNmapMacPrefixes, parseOuiCsv } from "./parse";

// Lines in the shape of the live file, including a quoted address that
// runs over two lines and an escaped quote.
const SAMPLE = `Registry,Assignment,Organization Name,Organization Address\r
MA-L,E80AB9,"Cisco Systems, Inc",80 West Tasman Drive San Jose CA US 94568 \r
MA-L,80BA16,Micas Networks Inc.," 250 Tasman Drive, Ste 170, San Jose, CA 95134 S
an Jose  US 95134 "\r
MA-L,00d478,"Cisco Systems, Inc",80 West Tasman Drive San Jose CA US 94568 \r
MA-L,ABCDEF,"The ""Quoted""   Company",Somewhere\r
MA-M,AABBCC1,Too Specific,Elsewhere\r
MA-L,XYZ123,Not Hex,Nowhere\r
`;

describe("parseOuiCsv", () => {
  const map = parseOuiCsv(SAMPLE);
  it("reads quoted names with commas", () => {
    expect(map.get("E80AB9")).toBe("Cisco Systems, Inc");
  });
  it("survives an address spanning two lines", () => {
    expect(map.get("80BA16")).toBe("Micas Networks Inc.");
    expect(map.get("00D478")).toBe("Cisco Systems, Inc");
  });
  it("unescapes quotes and collapses whitespace", () => {
    expect(map.get("ABCDEF")).toBe('The "Quoted" Company');
  });
  it("keeps only valid MA-L rows", () => {
    expect(map.size).toBe(4);
  });
});

describe("parseNmapMacPrefixes", () => {
  const map = parseNmapMacPrefixes(`# $Id: $ generated with make-mac-prefixes.pl
# Nmap additions to this file:
0030D6 MSC Vertriebs Gmbh
BC2411 Proxmox Server Solutions GmbH
70B3D5F Some MA-M Company
70B3D5ABC An MA-S   Company
NOTHEX Broken
`);
  it("reads 6, 7 and 9 digit prefixes", () => {
    expect(map.get("BC2411")).toBe("Proxmox Server Solutions GmbH");
    expect(map.get("70B3D5F")).toBe("Some MA-M Company");
    expect(map.get("70B3D5ABC")).toBe("An MA-S Company");
    expect(map.size).toBe(4);
  });
});
