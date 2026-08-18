import { describe, expect, it } from "vitest";
import { STATUS_LABEL, STATUS_RANK, worstOf } from "./useFleetHealth";

// worstOf is what decides both the Fleet Health page's overall banner and
// whether the Dashboard shows its "needs attention" link at all, from the
// same computation - so a wrong answer here is silently hidden trouble.
describe("worstOf", () => {
  it("returns ok only when every input is ok", () => {
    expect(worstOf("ok", "ok", "ok")).toBe("ok");
  });

  it("escalates to warning if any input is a warning", () => {
    expect(worstOf("ok", "warning", "ok")).toBe("warning");
  });

  it("lets critical win over any number of warnings, regardless of order", () => {
    expect(worstOf("warning", "critical", "warning")).toBe("critical");
    expect(worstOf("critical", "ok")).toBe("critical");
    expect(worstOf("ok", "critical")).toBe("critical");
  });

  it("defaults to ok with no inputs at all", () => {
    expect(worstOf()).toBe("ok");
  });

  it("ranks the three statuses in escalating order", () => {
    expect(STATUS_RANK.ok).toBeLessThan(STATUS_RANK.warning);
    expect(STATUS_RANK.warning).toBeLessThan(STATUS_RANK.critical);
  });

  it("has a display label for every status", () => {
    expect(STATUS_LABEL.ok).toBe("OK");
    expect(STATUS_LABEL.warning).toBe("Warning");
    expect(STATUS_LABEL.critical).toBe("Critical");
  });
});
