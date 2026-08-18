import { describe, expect, it } from "vitest";
import { cveSeverityClass } from "./cveSeverity";

describe("cveSeverityClass", () => {
  it("uses an explicit CVSS v3 severity when present, whatever its casing", () => {
    expect(cveSeverityClass({ cvssSeverity: "CRITICAL" })).toBe("critical");
    expect(cveSeverityClass({ cvssSeverity: "high" })).toBe("high");
    expect(cveSeverityClass({ cvssSeverity: "Medium" })).toBe("medium");
    expect(cveSeverityClass({ cvssSeverity: "LOW" })).toBe("low");
  });

  it("prefers the explicit severity over the numeric score when both disagree", () => {
    // A v3 entry carries both; the band nmap/NVD actually assigned wins
    // rather than re-deriving one from the score.
    expect(cveSeverityClass({ cvssSeverity: "LOW", cvssScore: 9.8 })).toBe("low");
  });

  it("derives a band from the score for CVSS v2-only entries with no severity string", () => {
    expect(cveSeverityClass({ cvssScore: 9.0 })).toBe("critical");
    expect(cveSeverityClass({ cvssScore: 10 })).toBe("critical");
    expect(cveSeverityClass({ cvssScore: 7.0 })).toBe("high");
    expect(cveSeverityClass({ cvssScore: 8.9 })).toBe("high");
    expect(cveSeverityClass({ cvssScore: 4.0 })).toBe("medium");
    expect(cveSeverityClass({ cvssScore: 6.9 })).toBe("medium");
    expect(cveSeverityClass({ cvssScore: 3.9 })).toBe("low");
    expect(cveSeverityClass({ cvssScore: 0 })).toBe("low");
  });

  it("falls back to low when neither a severity nor a score is known", () => {
    expect(cveSeverityClass({})).toBe("low");
    expect(cveSeverityClass({ cvssSeverity: null, cvssScore: null })).toBe("low");
  });

  it("ignores an unrecognized severity string and falls through to the score", () => {
    expect(cveSeverityClass({ cvssSeverity: "NONE", cvssScore: 9.5 })).toBe("critical");
  });
});
