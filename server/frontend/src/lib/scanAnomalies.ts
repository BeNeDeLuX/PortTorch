import type { ScanAnomaly } from "../api";

// The same wording the server logs, kept here rather than sent down with
// each row: the shape is small and stable, and a sentence travelling in
// every history response for every scan would be paying for prose the
// table mostly does not show.
//
// This is a deliberate second copy, the same trade-off as
// knownServiceTags.ts and knownNseScripts.ts - if the two ever disagree
// it is about phrasing, never about whether a scan was flagged.
export function describeScanAnomaly(anomaly: ScanAnomaly): string {
  if (anomaly.kind === "dominant_service") {
    const what = anomaly.product ?? anomaly.serviceName ?? "The same service";
    const share = Math.round((anomaly.hosts / anomaly.totalHosts) * 100);
    return (
      `${what} appears on ${anomaly.port}/${anomaly.protocol} of ${anomaly.hosts} of ${anomaly.totalHosts} hosts ` +
      `(${share}%). One device answering for the whole range looks exactly like this, and would be counted here as ` +
      `${anomaly.hosts} separate hosts.`
    );
  }
  return (
    `Discovery found ${anomaly.discovered} hosts; only ${anomaly.confirmed} could be confirmed to have an open port. ` +
    `The other ${anomaly.discovered - anomaly.confirmed} answered the discovery probe and nothing else.`
  );
}

export function anomalyLabel(anomaly: ScanAnomaly): string {
  return anomaly.kind === "dominant_service" ? "one service everywhere" : "mostly unconfirmed";
}
