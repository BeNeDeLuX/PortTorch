import { describe, expect, it } from "vitest";
import { lifecycleOf, parseVersion } from "./softwareLifecycle";

const at = (d: string) => new Date(`${d}T12:00:00Z`);

describe("parseVersion", () => {
  it("takes the leading dotted number", () => {
    expect(parseVersion("8.3.33")).toEqual([8, 3, 33]);
    expect(parseVersion("9.4.53.v20231009")).toEqual([9, 4, 53]);
    expect(parseVersion("v20.11.1")).toEqual([20, 11, 1]);
  });

  it("refuses strings that do not commit to one version", () => {
    expect(parseVersion("9.6.0 or later")).toBeNull();
    expect(parseVersion("3.X - 4.X")).toBeNull();
    expect(parseVersion("unknown")).toBeNull();
  });
});

describe("lifecycleOf", () => {
  it("flags an ended branch with its date, matching the names scanners report", () => {
    expect(lifecycleOf("PHP", "7.4.33", at("2026-10-01"))).toMatchObject({ status: "ended", branch: "7.4", date: "2022-11-28" });
    expect(lifecycleOf("Jetty", "9.4.53.v20231009", at("2026-10-01"))).toMatchObject({ status: "ended", branch: "9" });
    expect(lifecycleOf("Apache httpd", "2.2.34", at("2026-10-01"))?.status).toBe("ended");
    expect(lifecycleOf("Apache HTTP Server", "2.2.15", at("2026-10-01"))?.status).toBe("ended");
    expect(lifecycleOf("PostgreSQL DB", "12.4", at("2026-10-01"))).toMatchObject({ branch: "12", status: "ended" });
  });

  it("warns ahead of a scheduled end, and says nothing further out", () => {
    expect(lifecycleOf("PHP", "8.2.10", at("2026-10-01"))).toMatchObject({ status: "ending", date: "2026-12-31" });
    expect(lifecycleOf("PHP", "8.3.33", at("2026-10-01"))).toBeNull();
  });

  it("covers branches older than the table without listing each", () => {
    expect(lifecycleOf("PHP", "5.4.45", at("2026-10-01"))?.status).toBe("ended");
    expect(lifecycleOf("PostgreSQL DB", "9.2.24", at("2026-10-01"))?.branch).toBe("9.2");
  });

  it("tells Tomcat 8.0 and 8.5 apart", () => {
    expect(lifecycleOf("Apache Tomcat", "8.0.53", at("2026-10-01"))?.date).toBe("2018-06-30");
    expect(lifecycleOf("Apache Tomcat", "8.5.100", at("2026-10-01"))?.date).toBe("2024-03-31");
    expect(lifecycleOf("Apache Tomcat", "9.0.90", at("2026-10-01"))).toBeNull();
  });

  it("says nothing without a product it knows or a version it can read", () => {
    expect(lifecycleOf("OpenSSH", "7.4", at("2026-10-01"))).toBeNull();
    expect(lifecycleOf("nginx", "1.18.0", at("2026-10-01"))).toBeNull();
    expect(lifecycleOf("PostgreSQL DB", "9.6.0 or later", at("2026-10-01"))).toBeNull();
    expect(lifecycleOf("PHP", null, at("2026-10-01"))).toBeNull();
    expect(lifecycleOf("Python", "3.14", at("2026-10-01"))).toBeNull();
  });
});
