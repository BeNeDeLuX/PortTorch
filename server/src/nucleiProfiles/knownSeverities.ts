// nuclei's own severity enum - small and stable, unlike its tag taxonomy
// (see routes.ts's tag validation comment for why tags get no equivalent
// allowlist). Used both for the Nuclei Profiles admin page's checkboxes
// and for rejecting an unrecognized severity at profile-creation time.
export const KNOWN_NUCLEI_SEVERITIES: Set<string> = new Set(["unknown", "info", "low", "medium", "high", "critical"]);
