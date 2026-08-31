import { describe, expect, it } from "vitest";
import { sshKeyRisk, sshKeyRiskLabel } from "./sshKeyRisk";

describe("sshKeyRisk", () => {
  it("flags DSA regardless of the reported size", () => {
    expect(sshKeyRisk("ssh-dss", 1024)).toBe("dsa");
    expect(sshKeyRisk("ssh-dss", null)).toBe("dsa");
    // A DSA key claiming an unusual size is still DSA.
    expect(sshKeyRisk("ssh-dss", 3072)).toBe("dsa");
  });

  it("flags RSA below 2048 bits", () => {
    expect(sshKeyRisk("ssh-rsa", 1024)).toBe("weak-rsa");
    expect(sshKeyRisk("ssh-rsa", 2047)).toBe("weak-rsa");
  });

  it("accepts RSA at or above 2048 bits", () => {
    expect(sshKeyRisk("ssh-rsa", 2048)).toBe("ok");
    // The exact shape the scanner's own parser test captured from a real
    // OpenSSH 8.4 host.
    expect(sshKeyRisk("ssh-rsa", 3072)).toBe("ok");
    expect(sshKeyRisk("ssh-rsa", 4096)).toBe("ok");
  });

  it("says nothing about an RSA key whose size nmap did not report", () => {
    // null is missing data, not a small key - guessing here would put a
    // warning badge on healthy hosts.
    expect(sshKeyRisk("ssh-rsa", null)).toBe("ok");
  });

  it("leaves modern algorithms alone", () => {
    expect(sshKeyRisk("ssh-ed25519", 256)).toBe("ok");
    expect(sshKeyRisk("ecdsa-sha2-nistp256", 256)).toBe("ok");
    expect(sshKeyRisk("ecdsa-sha2-nistp521", 521)).toBe("ok");
  });

  it("normalises casing and stray whitespace in the key type", () => {
    expect(sshKeyRisk(" SSH-DSS ", 1024)).toBe("dsa");
    expect(sshKeyRisk("SSH-RSA", 1024)).toBe("weak-rsa");
  });

  it("does not classify an unknown key type", () => {
    expect(sshKeyRisk("sk-ssh-ed25519@openssh.com", 256)).toBe("ok");
    expect(sshKeyRisk("", null)).toBe("ok");
  });
});

describe("sshKeyRiskLabel", () => {
  it("labels the two flagged cases and stays empty otherwise", () => {
    expect(sshKeyRiskLabel("dsa")).toBe("DSA (deprecated)");
    expect(sshKeyRiskLabel("weak-rsa")).toBe("RSA < 2048 bits");
    expect(sshKeyRiskLabel("ok")).toBe("");
  });
});
