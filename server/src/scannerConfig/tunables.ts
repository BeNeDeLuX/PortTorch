// Which parts of a scanner's config.yaml an admin may change from the
// dashboard, and within what bounds.
//
// This is an allowlist, not a mirror of the whole config, and the
// exclusions are the important part:
//
//  - webserverUrl / apiKey / serverCaCertPath / insecureSkipVerify: the
//    scanner reaches the webserver through these, so a wrong value would
//    orphan it permanently - the one thing that can never be fixed
//    remotely, since fixing it needs the connection it just broke.
//  - every *Path: a wrong binary path breaks scanning outright and is
//    equally unfixable from here.
//  - listenAddr / controlApiToken: local REST surface, security-relevant,
//    and meaningless to set centrally.
//  - submitQueueDir / scanAuditLogPath: filesystem paths on a host this
//    webserver knows nothing about.
//  - pollIntervalSeconds / retryIntervalSeconds: read once when serve
//    starts its tickers, so changing them would need those loops rebuilt
//    mid-flight for very little gain - and a bad value would throttle the
//    very loop that fetches the correction.
//
// What's left is the operational tuning that actually gets changed in
// practice: how fast and how hard this scanner probes. Every one is a
// bounded integer, so a bad value is self-limiting rather than dangerous.
export interface ScannerTunable {
  key: string;
  label: string;
  min: number;
  max: number;
  help: string;
}

export const SCANNER_TUNABLES: ScannerTunable[] = [
  {
    key: "masscanRate",
    label: "masscan rate (packets/sec)",
    min: 1,
    max: 10_000_000,
    help: "Discovery pass speed. Lower it for fragile or sensitive segments.",
  },
  {
    key: "masscanRetries",
    label: "masscan retries",
    min: 0,
    max: 10,
    help: "Resends each probe. Higher finds more on lossy networks, at the cost of scan time.",
  },
  {
    key: "concurrency",
    label: "nmap concurrency",
    min: 1,
    max: 64,
    help: "How many hosts are enriched with nmap in parallel.",
  },
  {
    key: "gowitnessConcurrency",
    label: "Screenshot concurrency",
    min: 1,
    max: 16,
    help: "Each one is a full headless Chrome - raising this without the RAM to match makes them all time out together.",
  },
  {
    key: "screenshotTimeoutSeconds",
    label: "Screenshot timeout (seconds)",
    min: 1,
    max: 300,
    help: "How long gowitness may spend on one page.",
  },
  {
    key: "rdpConcurrency",
    label: "RDP screenshot concurrency",
    min: 1,
    max: 16,
    help: "Xvfb plus xfreerdp plus import per screenshot - as heavy as a Chrome instance.",
  },
  {
    key: "nucleiConcurrency",
    label: "nuclei concurrency",
    min: 1,
    max: 16,
    help: "Each run walks the whole selected template set against one target.",
  },
  {
    key: "nucleiTimeoutSeconds",
    label: "nuclei timeout (seconds)",
    min: 1,
    max: 3600,
    help: "How long one host's nuclei run may take.",
  },
  {
    key: "tlsCertTimeoutSeconds",
    label: "TLS certificate probe timeout (seconds)",
    min: 1,
    max: 120,
    help: "Handshake timeout when reading a certificate.",
  },
];

export type ScannerConfigOverrides = Record<string, number>;

export interface TunableValidationError {
  key: string;
  message: string;
}

// Returns the cleaned overrides, or the reasons it wouldn't accept them.
// An unknown key is rejected rather than dropped: silently ignoring a
// misspelled one would look exactly like the setting had been saved.
export function validateOverrides(
  input: Record<string, unknown>
): { ok: true; value: ScannerConfigOverrides } | { ok: false; errors: TunableValidationError[] } {
  const errors: TunableValidationError[] = [];
  const value: ScannerConfigOverrides = {};

  for (const [key, raw] of Object.entries(input)) {
    const tunable = SCANNER_TUNABLES.find((t) => t.key === key);
    if (!tunable) {
      errors.push({ key, message: "not a configurable setting" });
      continue;
    }
    if (typeof raw !== "number" || !Number.isInteger(raw)) {
      errors.push({ key, message: "must be a whole number" });
      continue;
    }
    if (raw < tunable.min || raw > tunable.max) {
      errors.push({ key, message: `must be between ${tunable.min} and ${tunable.max}` });
      continue;
    }
    value[key] = raw;
  }

  return errors.length > 0 ? { ok: false, errors } : { ok: true, value };
}
