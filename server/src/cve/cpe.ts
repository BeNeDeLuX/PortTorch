// nmap emits CPEs in the older "2.2" URI form (e.g. cpe:/a:openbsd:openssh:9.9),
// but the NVD REST API's cpeName parameter expects the "2.3" formatted
// string (cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*). This is a
// pragmatic conversion for the simple CPEs nmap actually produces
// (part:vendor:product:version[:update]), not a full implementation of
// the CPE 2.3 binding spec (e.g. the packed edition~sw_edition~... form is
// not unpacked) - real-world nmap output doesn't use those.
export function cpe22to23(cpe22: string): string | null {
  const match = /^cpe:\/([aho]?):?(.*)$/.exec(cpe22.trim());
  if (!match) return null;
  const part = match[1] || "a";
  const components = match[2]
    .split(":")
    .map((c) => (c === "" ? "*" : c));
  while (components.length < 10) components.push("*");
  return `cpe:2.3:${part}:${components.slice(0, 10).join(":")}`;
}
