import { describe, expect, it } from "vitest";
import { categorisePort, PORT_CATEGORY_ORDER } from "./portCategories";

describe("categorisePort", () => {
  it("maps well-known ports to their function", () => {
    expect(categorisePort(443, "tcp")).toBe("Web");
    expect(categorisePort(8443, "tcp")).toBe("Web");
    expect(categorisePort(22, "tcp")).toBe("Remote access");
    expect(categorisePort(3389, "tcp")).toBe("Remote access");
    expect(categorisePort(5432, "tcp")).toBe("Databases");
    expect(categorisePort(445, "tcp")).toBe("File sharing");
    expect(categorisePort(25, "tcp")).toBe("Mail");
    expect(categorisePort(389, "tcp")).toBe("Directory / auth");
    expect(categorisePort(161, "udp")).toBe("Network infrastructure");
    expect(categorisePort(502, "tcp")).toBe("Industrial / OT");
  });

  it("falls back to Other for anything unlisted", () => {
    expect(categorisePort(49152, "tcp")).toBe("Other");
    expect(categorisePort(1, "tcp")).toBe("Other");
  });

  // The whole reason the table is keyed on protocol as well as number.
  it("distinguishes the ports that mean different things per protocol", () => {
    expect(categorisePort(514, "udp")).toBe("Network infrastructure"); // syslog
    expect(categorisePort(514, "tcp")).toBe("Remote access"); // rsh
    expect(categorisePort(69, "udp")).toBe("File sharing"); // tftp
    expect(categorisePort(69, "tcp")).toBe("Other");
  });

  it("lists every category it can return, with Other last", () => {
    const seen = new Set<string>();
    for (let port = 0; port <= 65535; port++) {
      seen.add(categorisePort(port, "tcp"));
      seen.add(categorisePort(port, "udp"));
    }
    for (const category of seen) {
      expect(PORT_CATEGORY_ORDER).toContain(category);
    }
    expect(PORT_CATEGORY_ORDER[PORT_CATEGORY_ORDER.length - 1]).toBe("Other");
  });
});
