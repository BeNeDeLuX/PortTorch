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
// practice: how fast and how hard this scanner probes, plus how many
// scans it takes on at once. Every one is a bounded integer, so a bad
// value is self-limiting rather than dangerous.
//
// maxConcurrentScans is the one that isn't a pipeline setting - on the
// scanner it lives on the serve-mode config rather than pipeline.Config,
// and is applied by applyServeOverrides instead of applyConfigOverrides.
// It travels over the same wire in the same map, so nothing here needs to
// know the difference.
export interface ScannerTunable {
  key: string;
  label: string;
  min: number;
  max: number;
  help: string;
  // The value a freshly installed scanner uses - copied from
  // scanner/internal/config/config.go's defaults(), which is the source
  // of truth. A fourth hand-kept copy of scanner-side constants, same
  // accepted trade-off as knownNseScripts.ts and the three compareSemver
  // implementations: shared packaging across a Go and a TS component
  // isn't worth the coupling for a handful of numbers.
  //
  // It is the *shipped* default, deliberately not "this scanner's current
  // value" - the webserver cannot read a scanner's config.yaml, so an
  // operator who edited that file has a different fallback and the UI
  // must say so rather than implying otherwise.
  defaultValue: number;
}

export const SCANNER_TUNABLES: ScannerTunable[] = [
  {
    key: "maxConcurrentScans",
    defaultValue: 1,
    label: "Concurrent scans",
    min: 1,
    max: 8,
    help: "How many queued scan requests this scanner works on at once. 1 (the default) means a wide or UDP sweep blocks every other request until it finishes. Each concurrent scan runs its own masscan/nmap and its own screenshot/nuclei workers, so this multiplies load rather than dividing it.",
  },
  {
    key: "masscanRate",
    defaultValue: 1000,
    label: "masscan rate (packets/sec)",
    min: 1,
    max: 10_000_000,
    help: "Discovery pass speed. Lower it for fragile or sensitive segments.",
  },
  {
    key: "masscanRetries",
    defaultValue: 2,
    label: "masscan retries",
    min: 0,
    max: 10,
    help: "Resends each probe. Higher finds more on lossy networks, at the cost of scan time.",
  },
  {
    key: "concurrency",
    defaultValue: 5,
    label: "nmap concurrency",
    min: 1,
    max: 64,
    help: "How many hosts are enriched with nmap in parallel.",
  },
  {
    key: "gowitnessConcurrency",
    defaultValue: 2,
    label: "Screenshot concurrency",
    min: 1,
    max: 16,
    help: "Each one is a full headless Chrome - raising this without the RAM to match makes them all time out together.",
  },
  {
    key: "screenshotTimeoutSeconds",
    defaultValue: 20,
    label: "Screenshot timeout (seconds)",
    min: 1,
    max: 300,
    help: "How long gowitness may spend on one page.",
  },
  {
    key: "rdpConcurrency",
    defaultValue: 2,
    label: "RDP screenshot concurrency",
    min: 1,
    max: 16,
    help: "Xvfb plus xfreerdp plus import per screenshot - as heavy as a Chrome instance.",
  },
  {
    key: "nucleiConcurrency",
    defaultValue: 2,
    label: "nuclei concurrency",
    min: 1,
    max: 16,
    help: "Each run walks the whole selected template set against one target.",
  },
  {
    key: "nucleiTimeoutSeconds",
    defaultValue: 10,
    label: "nuclei timeout (seconds)",
    min: 1,
    max: 3600,
    help: "How long one host's nuclei run may take.",
  },
  {
    key: "tlsCertTimeoutSeconds",
    defaultValue: 8,
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
