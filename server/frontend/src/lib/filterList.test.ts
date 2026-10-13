import { describe, expect, it } from "vitest";
import { joinFilterList, parseFilterList } from "./filterList";

describe("filter lists", () => {
  it("round-trips values containing commas", () => {
    const values = ["Icann, Iana Department", "-Cisco Systems, Inc", "Ubiquiti"];
    expect(parseFilterList(joinFilterList(values))).toEqual(values);
  });
  it("reads an unescaped list exactly as before", () => {
    expect(parseFilterList("443,-53, 80 ,")).toEqual(["443", "-53", "80"]);
  });
  it("keeps a literal backslash", () => {
    expect(parseFilterList(joinFilterList(["a\\b", "c"]))).toEqual(["a\\b", "c"]);
  });
});
