import { useEffect, useRef, useState } from "react";
import { api, ScanJobProgress } from "../api";
import Modal from "./Modal";

// masscan/discovery are the scan's up-front port-discovery step (nmap
// discovery replaces masscan for IPv6 targets - see CLAUDE.md's "IPv6
// targets" section) - everything after that (nmap enrichment, and the
// gowitness/RDP/TLS workers + host submissions that stream concurrently
// with it, see "Scan pipeline") is grouped into one second phase rather
// than invented as separate numbered phases, since those genuinely run
// concurrently with nmap rather than after it - a strict "phase 3/4/5"
// would misrepresent that as sequential when it isn't.
const DISCOVERY_STAGES = new Set(["masscan", "discovery"]);

function phaseFor(stage: string | null): 1 | 2 | null {
  if (!stage) return null;
  return DISCOVERY_STAGES.has(stage) ? 1 : 2;
}

const POLL_INTERVAL_MS = 3000;

export default function ScanProgressModal({ jobId, onClose }: { jobId: string; onClose: () => void }) {
  const [progress, setProgress] = useState<ScanJobProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Only ever increases within one modal session - once the scan has
  // reached phase 2 it never legitimately goes back to phase 1, so this
  // avoids the phase indicator flickering backward if a stale poll
  // response ever raced in out of order.
  const maxPhaseSeen = useRef<1 | 2>(1);
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
      } catch {
        if (!cancelled) setError("Could not load scan progress.");
      }
    }
    load();
    const interval = setInterval(load, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [jobId]);

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
            <li className={phase === 2 ? "active" : ""}>
              2. Enrichment &amp; submission <span className="host-meta">(nmap, screenshots, certificates)</span>
            </li>
          </ol>

          {progress.stageDetail && <p className="scan-phase-detail">{progress.stageDetail}</p>}

          {progress.logs.length === 0 ? (
            <p className="empty">No progress reported yet - the scanner pushes an update every few seconds once the scan starts.</p>
          ) : (
            <div className="scan-log-feed">
              {progress.logs.map((line, i) => (
                <div key={i} className="scan-log-line">
                  <span className="host-meta">{new Date(line.time).toLocaleTimeString()}</span>{" "}
                  <span className="scan-log-stage">[{line.stage}]</span> {line.message}
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
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
