import { describe, expect, it } from "vitest";
import { groupsFrom, readClaim, roleForGroups } from "./oidc";

const mapping = {
  adminGroups: ["PortTorch-Admins"],
  operatorGroups: ["analysts"],
  userGroups: ["viewers"],
  defaultRole: null,
};

describe("roleForGroups", () => {
  it("grants the highest role any group maps to", () => {
    expect(roleForGroups(["viewers", "analysts"], mapping)).toBe("operator");
    expect(roleForGroups(["analysts", "porttorch-admins"], mapping)).toBe("admin");
    expect(roleForGroups(["viewers"], mapping)).toBe("user");
  });

  it("compares group names case-insensitively", () => {
    expect(roleForGroups(["PORTTORCH-ADMINS"], mapping)).toBe("admin");
  });

  it("refuses by default, or grants the configured fallback", () => {
    expect(roleForGroups(["staff"], mapping)).toBeNull();
    expect(roleForGroups([], { ...mapping, defaultRole: "user" })).toBe("user");
    // The fallback can never be admin: the type does not allow it, and a
    // group mapping is the only way to that role.
    expect(roleForGroups(["staff"], { ...mapping, defaultRole: "operator" })).toBe("operator");
  });
});

describe("claims", () => {
  it("reads nested claims by dotted path, as Keycloak nests realm roles", () => {
    const claims = { realm_access: { roles: ["analysts", "offline_access"] }, groups: "a, b" };
    expect(readClaim(claims, "realm_access.roles")).toEqual(["analysts", "offline_access"]);
    expect(groupsFrom(claims, "realm_access.roles")).toEqual(["analysts", "offline_access"]);
    expect(readClaim(claims, "realm_access.missing.deeper")).toBeUndefined();
  });

  it("accepts a group list given as one string, and ignores what is not a name", () => {
    expect(groupsFrom({ groups: "a, b c" }, "groups")).toEqual(["a", "b", "c"]);
    expect(groupsFrom({ groups: ["a", 3, null, "b"] }, "groups")).toEqual(["a", "b"]);
    expect(groupsFrom({}, "groups")).toEqual([]);
  });
});
