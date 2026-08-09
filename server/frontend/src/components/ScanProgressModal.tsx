import { useEffect, useRef, useState } from "react";
import { api, ScanJobProgress } from "../api";
import Modal from "./Modal";

// masscan/discovery are the scan's up-front port-discovery step (nmap
// discovery replaces masscan for IPv6 targets - see CLAUDE.md's "IPv6
// targets" section) and always fully finishes before anything below can
// start (see "Scan pipeline" - the gowitness/RDP/TLS worker pools only
// ever consume jobs nmap's own pool enqueues, and that pool only starts
// once discovery has a host list) - so phase 1 is genuinely sequential
// and safe to show as a single done/active step.
const DISCOVERY_STAGES = new Set(["masscan", "discovery"]);

function phaseFor(stage: string | null): 1 | 2 | null {
  if (!stage) return null;
  return DISCOVERY_STAGES.has(stage) ? 1 : 2;
}

// Everything phase 1 isn't. These five genuinely run concurrently once
// nmap's worker pool starts (nmap enrichment, and the gowitness/RDP/TLS
// screenshot/cert workers + host submissions that stream alongside it -
// see "Scan pipeline"), so this is deliberately a checklist of "have we
// seen any activity from this stage yet", not a numbered "phase 3/4/5..."
// sequence - a strict linear phase list would misrepresent concurrent
// work as sequential. A scan with no RDP-classified ports, for example,
// will simply never mark "RDP capture" seen, which is accurate (there
// was nothing for that worker pool to do), not a stuck step.
const CONCURRENT_STAGES: Array<{ key: string; label: string }> = [
  { key: "nmap", label: "Nmap (service/version enrichment)" },
  { key: "gowitness", label: "Screenshots (gowitness)" },
  { key: "tls", label: "TLS certificates" },
  { key: "rdp", label: "RDP capture" },
  { key: "snmp", label: "SNMP probe" },
  { key: "submit", label: "Submitting results" },
];

const POLL_INTERVAL_MS = 3000;

export default function ScanProgressModal({
  jobId,
  onClose,
  live = true,
}: {
  jobId: string;
  onClose: () => void;
  // false for a scan that's already finished (Scan History) - fetches the
  // final snapshot once instead of polling every 3s forever for data that
  // can no longer change.
  live?: boolean;
}) {
  const [progress, setProgress] = useState<ScanJobProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Only ever increases within one modal session - once the scan has
  // reached phase 2 it never legitimately goes back to phase 1, so this
  // avoids the phase indicator flickering backward if a stale poll
  // response ever raced in out of order.
  const maxPhaseSeen = useRef<1 | 2>(1);
  // Union of every stage seen across every poll this session, not just
  // whatever's in the latest 100-line snapshot - the scanner's buffer is
  // capped, so an early, already-finished activity (e.g. gowitness on a
  // scan with few HTTP(S) ports) can otherwise scroll out of view before
  // we ever poll again, making it look like it never ran at all.
  const [seenStages, setSeenStages] = useState<Set<string>>(new Set());
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const result = await api.scanJobProgress(jobId);
        if (cancelled) return;
        setProgress(result);
        setError(null);
        const phase = phaseFor(result.currentStage);
        if (phase && phase > maxPhaseSeen.current) {
          maxPhaseSeen.current = phase;
        }
        setSeenStages((prev) => {
          const next = new Set(prev);
          for (const line of result.logs) next.add(line.stage);
          if (result.currentStage) next.add(result.currentStage);
          return next;
        });
      } catch {
        if (!cancelled) setError("Could not load scan progress.");
      }
    }
    load();
    if (!live) {
      return () => {
        cancelled = true;
      };
    }
    const interval = setInterval(load, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [jobId, live]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ block: "end" });
  }, [progress?.logs.length]);

  const phase = phaseFor(progress?.currentStage ?? null);

  return (
    <Modal title="Scan details" onClose={onClose}>
      {error && <p className="error">{error}</p>}

      {!progress && !error && <p>Loading...</p>}

      {progress && (
        <>
          <ol className="scan-phase-tracker">
            <li className={phase === 1 ? "active" : maxPhaseSeen.current > 1 ? "done" : ""}>
              1. Discovery <span className="host-meta">(masscan)</span>
            </li>
          </ol>

          {maxPhaseSeen.current > 1 && (
            <div className="scan-phase-2">
              <p className="scan-phase-2-label">
                2. Enrichment &amp; streaming <span className="host-meta">(these run concurrently, not in order)</span>
              </p>
              <ul className="scan-activity-checklist">
                {CONCURRENT_STAGES.map((s) => (
                  <li
                    key={s.key}
                    className={progress.currentStage === s.key ? "active" : seenStages.has(s.key) ? "seen" : ""}
                  >
                    <span className="scan-activity-dot" aria-hidden="true" />
                    {s.label}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {progress.stageDetail && <p className="scan-phase-detail">{progress.stageDetail}</p>}

          {progress.logs.length === 0 ? (
            <p className="empty">
              {live
                ? "No progress reported yet - the scanner pushes an update every few seconds once the scan starts."
                : "No progress log was recorded for this scan - it may predate this feature, or the scanner never reported before the scan finished."}
            </p>
          ) : (
            <>
              {!live && (
                <p className="host-meta scan-progress-historical-note">
                  {progress.logsComplete
                    ? `Complete log for this scan (${progress.logs.length} line${progress.logs.length === 1 ? "" : "s"}).`
                    : `Final snapshot from the scanner (last ${progress.logs.length} log line${progress.logs.length === 1 ? "" : "s"}) - earlier lines from this scan were not kept.`}
                </p>
              )}
              <div className="scan-log-feed">
                {progress.logs.map((line, i) => (
                  <div key={i} className="scan-log-line">
                    <span className="host-meta">{new Date(line.time).toLocaleTimeString()}</span>{" "}
                    <span className="scan-log-stage">[{line.stage}]</span> {line.message}
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            </>
          )}

          {progress.updatedAt && (
            <p className="host-meta scan-progress-updated">
              Last update from scanner: {new Date(progress.updatedAt).toLocaleTimeString()}
            </p>
          )}
        </>
      )}
    </Modal>
  );
}
