import { describe, expect, it } from "vitest";
import { progressView } from "./scanProgress";

const counts = (discoveryBlocks: number, discoveryBlocksDone: number, hostsDiscovered: number, hostsProcessed: number) => ({
  discoveryBlocks,
  discoveryBlocksDone,
  hostsDiscovered,
  hostsProcessed,
});

describe("progressView", () => {
  it("shows nothing for a scanner that sent no counts", () => {
    expect(progressView(null)).toEqual({ discovery: null, hosts: null, nothingFound: false });
  });

  it("shows no bar while a single masscan pass is still running", () => {
    // masscan reports every host at once at the end of its pass, so
    // there is no honest partial figure before that.
    const v = progressView(counts(1, 0, 0, 0));
    expect(v.hosts).toBeNull();
    expect(v.discovery).toBeNull();
  });

  it("measures hosts once discovery has reported", () => {
    const v = progressView(counts(1, 1, 40, 10));
    expect(v.hosts).toEqual({ processed: 10, discovered: 40, percent: 25, final: true });
  });

  it("never claims 100% while a host is still being worked on", () => {
    expect(progressView(counts(1, 1, 200, 199)).hosts?.percent).toBe(99);
    expect(progressView(counts(1, 1, 200, 200)).hosts?.percent).toBe(100);
  });

  it("marks the host total provisional while blocks remain", () => {
    const v = progressView(counts(8, 3, 12, 12));
    expect(v.discovery).toEqual({ done: 3, total: 8, percent: 37 });
    // All hosts found so far are done, but five blocks may add more.
    expect(v.hosts).toMatchObject({ percent: 100, final: false });
  });

  it("says when discovery finished and found nothing", () => {
    expect(progressView(counts(1, 1, 0, 0)).nothingFound).toBe(true);
    // Not yet: later blocks can still turn something up.
    expect(progressView(counts(4, 2, 0, 0)).nothingFound).toBe(false);
  });

  it("clamps an inconsistent push rather than drawing past the end", () => {
    expect(progressView(counts(1, 1, 5, 7)).hosts).toMatchObject({ processed: 5, percent: 100 });
  });
});
