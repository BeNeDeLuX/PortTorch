import { describe, expect, it } from "vitest";
import { isIPv4, isIPv4Cidr, isIPv4Range, isIPv6, isIPv6Cidr } from "./net";

describe("isIPv4", () => {
  it("accepts a plain IPv4 address", () => {
    expect(isIPv4("10.0.0.5")).toBe(true);
  });

  it("rejects an IPv6 address", () => {
    expect(isIPv4("::1")).toBe(false);
  });

  it("rejects garbage", () => {
    expect(isIPv4("not-an-ip")).toBe(false);
    expect(isIPv4("10.0.0.999")).toBe(false);
  });
});

describe("isIPv4Cidr", () => {
  it("accepts a valid CIDR range", () => {
    expect(isIPv4Cidr("10.0.0.0/24")).toBe(true);
    expect(isIPv4Cidr("192.168.1.1/32")).toBe(true);
    expect(isIPv4Cidr("0.0.0.0/0")).toBe(true);
  });

  it("rejects a prefix out of range", () => {
    expect(isIPv4Cidr("10.0.0.0/33")).toBe(false);
    expect(isIPv4Cidr("10.0.0.0/-1")).toBe(false);
  });

  it("rejects a plain IP with no prefix", () => {
    expect(isIPv4Cidr("10.0.0.0")).toBe(false);
  });

  it("rejects a malformed address", () => {
    expect(isIPv4Cidr("10.0.0.999/24")).toBe(false);
  });
});

describe("isIPv4Range", () => {
  it("accepts a valid ascending range", () => {
    expect(isIPv4Range("10.0.0.1-10.0.0.10")).toBe(true);
  });

  it("accepts a single-address range (start === end)", () => {
    expect(isIPv4Range("10.0.0.5-10.0.0.5")).toBe(true);
  });

  it("rejects a descending range (start after end)", () => {
    expect(isIPv4Range("10.0.0.10-10.0.0.1")).toBe(false);
  });

  it("rejects a range spanning octet boundaries the wrong way round", () => {
    // 10.0.1.0 > 10.0.0.255 numerically, so this is still descending.
    expect(isIPv4Range("10.0.1.0-10.0.0.255")).toBe(false);
  });

  it("rejects malformed endpoints", () => {
    expect(isIPv4Range("10.0.0.1-not-an-ip")).toBe(false);
    expect(isIPv4Range("10.0.0.1")).toBe(false);
  });
});

describe("isIPv6", () => {
  it("accepts a plain IPv6 address", () => {
    expect(isIPv6("2001:db8::1")).toBe(true);
    expect(isIPv6("::1")).toBe(true);
  });

  it("rejects an IPv4 address", () => {
    expect(isIPv6("10.0.0.5")).toBe(false);
  });

  it("rejects garbage", () => {
    expect(isIPv6("not-an-ip")).toBe(false);
  });
});

describe("isIPv6Cidr", () => {
  it("accepts a valid CIDR range", () => {
    expect(isIPv6Cidr("2001:db8::/32")).toBe(true);
    expect(isIPv6Cidr("::1/128")).toBe(true);
    expect(isIPv6Cidr("::/0")).toBe(true);
  });

  it("rejects a prefix out of range", () => {
    expect(isIPv6Cidr("2001:db8::/129")).toBe(false);
    expect(isIPv6Cidr("2001:db8::/-1")).toBe(false);
  });

  it("rejects a plain address with no prefix", () => {
    expect(isIPv6Cidr("2001:db8::1")).toBe(false);
  });

  it("rejects an IPv4 CIDR", () => {
    expect(isIPv6Cidr("10.0.0.0/24")).toBe(false);
  });
});
