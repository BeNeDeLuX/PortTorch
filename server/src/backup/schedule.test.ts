import { describe, expect, it } from "vitest";
import { archivesToPrune } from "./schedule";

describe("archivesToPrune", () => {
  const names = [
    "porttorch-20261001-020000Z.tar.gz",
    "porttorch-20261003-020000Z.tar.gz",
    "porttorch-20261002-020000Z.tar.gz",
    "notes.txt",
    "porttorch-20261003-020000Z.tar.gz.partial",
    "someone-elses-backup.tar.gz",
  ];

  it("keeps the newest archives and prunes the oldest", () => {
    expect(archivesToPrune(names, 2)).toEqual(["porttorch-20261001-020000Z.tar.gz"]);
    expect(archivesToPrune(names, 1)).toEqual(["porttorch-20261001-020000Z.tar.gz", "porttorch-20261002-020000Z.tar.gz"]);
  });

  it("never touches a file it did not write, or one still being written", () => {
    const pruned = archivesToPrune(names, 0);
    expect(pruned).not.toContain("notes.txt");
    expect(pruned).not.toContain("someone-elses-backup.tar.gz");
    expect(pruned).not.toContain("porttorch-20261003-020000Z.tar.gz.partial");
  });

  it("matches object keys under a prefix by their file name", () => {
    expect(archivesToPrune(["porttorch/porttorch-20261001-020000Z.tar.gz", "porttorch/porttorch-20261002-020000Z.tar.gz"], 1)).toEqual([
      "porttorch/porttorch-20261001-020000Z.tar.gz",
    ]);
  });
});
