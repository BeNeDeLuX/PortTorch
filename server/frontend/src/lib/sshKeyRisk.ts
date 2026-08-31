// Classifies an SSH host key by the algorithm and key size nmap's own
// ssh-hostkey script reported (key_type values are nmap's verbatim:
// "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", ...).
//
// Deliberately narrow: only two things are called out, and both are
// defensible without knowing anything about the host. Everything else -
// including ECDSA and Ed25519 - is "ok" rather than guessed at, because a
// badge that fires on healthy keys is a badge people learn to ignore.
export type SshKeyRisk = "dsa" | "weak-rsa" | "ok";

// Below this, an RSA host key is genuinely too small: 1024-bit RSA has
// been rejected by OpenSSH's own defaults for years.
const MIN_RSA_BITS = 2048;

export function sshKeyRisk(keyType: string, bits: number | null): SshKeyRisk {
  const type = keyType.trim().toLowerCase();

  // DSA is fixed at 1024 bits by the standard and has been disabled by
  // default in OpenSSH since 7.0 - the size never matters, the algorithm
  // itself is the finding.
  if (type === "ssh-dss" || type === "dsa") return "dsa";

  // bits is nullable in the schema (nmap doesn't always report it), and a
  // missing size is not evidence of a small key - say nothing.
  if ((type === "ssh-rsa" || type === "rsa") && bits !== null && bits < MIN_RSA_BITS) {
    return "weak-rsa";
  }

  return "ok";
}

export function sshKeyRiskLabel(risk: SshKeyRisk): string {
  switch (risk) {
    case "dsa":
      return "DSA (deprecated)";
    case "weak-rsa":
      return `RSA < ${MIN_RSA_BITS} bits`;
    default:
      return "";
  }
}
