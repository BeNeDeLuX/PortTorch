import { describe, expect, it } from "vitest";
import { displayHostname, identitySourceLabel } from "./derivedIdentity";

describe("displayHostname", () => {
  it("prefers the real hostname and never marks it derived", () => {
    const result = displayHostname({
      hostname: "filer01.corp.example.internal",
      derived_hostname: "FILER02",
      derived_hostname_source: "nbstat",
    });
    expect(result).toEqual({ name: "filer01.corp.example.internal", derived: false, source: null });
  });

  // The whole reason this helper exists: a derived name is shown, but the
  // caller is always told it is one, so it can never render as if it came
  // from DNS.
  it("falls back to the derived name and flags it, with its source", () => {
    const result = displayHostname({
      hostname: null,
      derived_hostname: "ws-app-01.corp.example.internal",
      derived_hostname_source: "rdp-certificate",
    });
    expect(result).toEqual({
      name: "ws-app-01.corp.example.internal",
      derived: true,
      source: "rdp-certificate",
    });
  });

  it("reports no name rather than an empty one", () => {
    expect(displayHostname({ hostname: null, derived_hostname: null, derived_hostname_source: null })).toEqual({
      name: null,
      derived: false,
      source: null,
    });
  });
});

describe("identitySourceLabel", () => {
  it("names each source in words", () => {
    expect(identitySourceLabel("rdp-certificate")).toContain("RDP certificate");
    expect(identitySourceLabel("smb-os-discovery")).toContain("SMB");
    expect(identitySourceLabel("nbstat")).toContain("NetBIOS");
  });

  // A scanner newer than this frontend can send a source it has never
  // heard of; showing the raw name beats showing nothing.
  it("passes an unknown source through rather than dropping it", () => {
    expect(identitySourceLabel("something-new")).toBe("from something-new");
  });

  it("still says something when there is no source at all", () => {
    expect(identitySourceLabel(null)).toBe("derived from scan data");
  });
});
