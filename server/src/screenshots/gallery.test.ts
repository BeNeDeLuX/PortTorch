import { describe, expect, it } from "vitest";
import { filterGallery, matchesKeyword, normalise, parseGalleryParams, type GalleryTile } from "./gallery";

const tile = (id: string, searchText: string, over: Partial<GalleryTile> = {}): GalleryTile => ({
  id,
  host_id: `h-${id}`,
  kind: "web",
  captured_at: "2026-10-01T10:00:00Z",
  changed: false,
  searchText,
  ...over,
});

const tiles = [
  tile("phone", "10.0.0.5 Cisco IP Phone 8841 SEP00AABBCC", { captured_at: "2026-10-03T10:00:00Z" }),
  tile("switch", "10.0.0.6 Catalyst 2960 Switch login", { mac_vendor: "Cisco" }),
  tile("nas", "10.0.0.7 Synology DiskStation", { kind: "rdp" }),
  tile("printer", "10.0.0.8 HP LaserJet Embedded Web Server", { changed: true, captured_at: "2026-10-02T10:00:00Z" }),
];
const tags = new Map([
  ["h-nas", ["storage", "managed"]],
  ["h-printer", ["managed"]],
]);
const run = (query: Record<string, unknown>) => filterGallery(tiles, tags, parseGalleryParams(query));
const ids = (r: ReturnType<typeof run>) => r.items.map((i) => i.id);

describe("keywords", () => {
  it("match however the vendor spells them", () => {
    const hay = normalise("Cisco IP-Phone 8841");
    expect(matchesKeyword(hay, "ipphone")).toBe(true);
    expect(matchesKeyword(hay, "IP Phone")).toBe(true);
    expect(matchesKeyword(hay, "ip-phone")).toBe(true);
    expect(matchesKeyword(hay, "  ")).toBe(false);
  });

  it("hide every tile that names one, and say how many", () => {
    const r = run({ exclude: "ipphone, switch" });
    expect(ids(r)).toEqual(["printer", "nas"]);
    expect(r.excluded).toBe(2);
  });
});

describe("tags", () => {
  it("narrow to hosts carrying any of them, or hide those that do", () => {
    expect(ids(run({ tags: "managed" })).sort()).toEqual(["nas", "printer"]);
    expect(ids(run({ excludeTags: "Storage" }))).toEqual(["phone", "printer", "switch"]);
  });

  it("are searchable, and listed with how many tiles carry each", () => {
    expect(ids(run({ q: "storage" }))).toEqual(["nas"]);
    expect(run({}).tags).toEqual([
      { tag: "managed", count: 2 },
      { tag: "storage", count: 1 },
    ]);
  });
});

describe("paging and counts", () => {
  it("pages newest first and clamps a page past the end", () => {
    const first = run({ pageSize: "2" });
    expect(ids(first)).toEqual(["phone", "printer"]);
    expect(first.total).toBe(4);
    expect(run({ pageSize: "2", page: "9" })).toMatchObject({ page: 2 });
  });

  it("counts the kinds among what the other filters left", () => {
    const r = run({ exclude: "synology" });
    expect(r.counts).toEqual({ all: 3, web: 3, rdp: 0, changed: 1 });
    expect(ids(run({ kind: "changed" }))).toEqual(["printer"]);
  });

  it("does not send the matching text to the browser, and caps the page size", () => {
    expect(run({}).items[0]).not.toHaveProperty("searchText");
    expect(parseGalleryParams({ pageSize: "100000" }).pageSize).toBe(200);
    expect(parseGalleryParams({ kind: "bogus" }).kind).toBe("all");
  });
});
