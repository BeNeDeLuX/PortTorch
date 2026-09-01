import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { NmapXmlParseError, parseNmapXml } from "./nmapXml";

// Captured from a real `nmap -sV` run (nmap 7.99, Alpine, against two
// local listeners plus one closed port) rather than hand-written, so the
// awkward parts are the ones nmap actually produces - notably a servicefp
// attribute full of &quot;-escaped probe transcripts, and a closed port
// that still carries a <service> element from nmap's port-number table.
const REAL_SAMPLE = readFileSync(path.join(__dirname, "../../tests/fixtures/nmap-real-sample.xml"), "utf8");

describe("parseNmapXml against real nmap output", () => {
  it("extracts the host, its hostname and only the open ports", () => {
    const scan = parseNmapXml(REAL_SAMPLE);
    expect(scan.hosts).toHaveLength(1);

    const host = scan.hosts[0];
    expect(host.ip).toBe("127.0.0.1");
    expect(host.hostname).toBe("localhost");

    // 9999 was scanned and came back closed - dropped here, because the
    // ingest path derives closures from the job's port spec instead, and
    // does it protocol-aware and only for ports the scan covered.
    expect(host.ports.map((p) => p.port).sort()).toEqual([2222, 8080]);
    expect(host.ports.every((p) => p.state === "open")).toBe(true);
  });

  it("carries service detection through, including CPEs", () => {
    const ssh = parseNmapXml(REAL_SAMPLE).hosts[0].ports.find((p) => p.port === 2222)!;
    expect(ssh.serviceName).toBe("ssh");
    expect(ssh.serviceProduct).toBe("OpenSSH");
    expect(ssh.serviceVersion).toBe("9.2p1 Debian 2");
    expect(ssh.extraInfo).toBe("protocol 2.0");
    expect(ssh.osType).toBe("Linux");
    // A single <cpe> child and several must both come out as a list.
    expect(ssh.cpes).toEqual(["cpe:/a:openbsd:openssh:9.2p1", "cpe:/o:linux:linux_kernel"]);
  });

  it("recovers the scanned port spec from <scaninfo>, not from the args string", () => {
    // This is what lets an import close ports the way a real scan does.
    expect(parseNmapXml(REAL_SAMPLE).portSpec).toBe("2222,8080,9999");
  });

  it("reports nmap's own argv back for confirmation", () => {
    expect(parseNmapXml(REAL_SAMPLE).args).toContain("nmap -sV -p 8080,2222,9999");
  });
});

describe("parseNmapXml shapes that a single real sample cannot cover", () => {
  const wrap = (inner: string) =>
    `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap x" version="7.99">${inner}</nmaprun>`;

  it("counts down hosts instead of importing or dropping them silently", () => {
    const scan = parseNmapXml(
      wrap(
        `<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>` +
          `<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>`
      )
    );
    expect(scan.hostsDown).toBe(1);
    expect(scan.hosts.map((h) => h.ip)).toEqual(["10.0.0.1"]);
  });

  it("handles a single port as well as several", () => {
    // fast-xml-parser would otherwise give an object for one and an array
    // for two - the classic "works with two ports, crashes with one" bug.
    const one = parseNmapXml(
      wrap(
        `<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>` +
          `<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>`
      )
    );
    expect(one.hosts[0].ports).toHaveLength(1);
  });

  it("records a UDP open|filtered result as open", () => {
    // The strongest statement nmap makes about an unanswered UDP probe;
    // treating it as anything else would make every UDP import empty.
    const scan = parseNmapXml(
      wrap(
        `<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>` +
          `<ports><port protocol="udp" portid="53"><state state="open|filtered"/></port></ports></host>`
      )
    );
    expect(scan.hosts[0].ports).toEqual([expect.objectContaining({ port: 53, protocol: "udp", state: "open" })]);
  });

  it("prefixes UDP ports in the reconstructed spec and merges both scan types", () => {
    const scan = parseNmapXml(
      wrap(`<scaninfo type="syn" protocol="tcp" services="80,443"/><scaninfo type="udp" protocol="udp" services="53"/>`)
    );
    expect(scan.portSpec).toBe("80,443,U:53");
  });

  it("keeps MAC and OS classification when nmap reported them", () => {
    const scan = parseNmapXml(
      wrap(
        `<host><status state="up"/>` +
          `<address addr="10.0.0.1" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco Systems"/>` +
          `<os><osmatch name="Linux 5.x" accuracy="97"><osclass type="general purpose" vendor="Linux" osfamily="Linux"/></osmatch></os>` +
          `</host>`
      )
    );
    const host = scan.hosts[0];
    expect(host.macAddress).toBe("00:11:22:33:44:55");
    expect(host.macVendor).toBe("Cisco Systems");
    expect(host.osName).toBe("Linux 5.x");
    expect(host.osFamily).toBe("Linux");
    expect(host.osAccuracy).toBe(97);
    expect(host.deviceType).toBe("general purpose");
  });

  it("rejects input that is not an nmap report", () => {
    expect(() => parseNmapXml("<other><thing/></other>")).toThrow(NmapXmlParseError);
    expect(() => parseNmapXml("not xml at all <<<")).toThrow(NmapXmlParseError);
  });
});
