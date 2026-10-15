import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, Me, RunComparison } from "../api";
import { formatDateTime } from "../lib/formatDate";
import Modal from "./Modal";

// A scheduled run against the schedule's run before it - see the server's
// GET /api/scan-jobs/:id/compare-previous for exactly what each list means.
export default function RunCompareModal({ jobId, me, onClose }: { jobId: string; me: Me; onClose: () => void }) {
  const [data, setData] = useState<RunComparison | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .compareWithPreviousRun(jobId)
      .then(setData)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not compare"));
  }, [jobId]);

  const section = (
    title: string,
    list: { items: Array<{ hostId: string; ip: string; hostname: string | null; port?: string; service?: string | null }>; total: number },
    empty: string
  ) => (
    <>
      <h4>
        {title} ({list.total})
      </h4>
      {list.total === 0 ? (
        <p className="empty">{empty}</p>
      ) : (
        <ul className="compare-list">
          {list.items.map((h, i) => (
            <li key={`${h.hostId}-${h.port ?? ""}-${i}`}>
              <Link to={`/hosts/${h.hostId}`}>{h.ip}</Link>
              {h.hostname && <span className="host-meta"> {h.hostname}</span>}
              {h.port && (
                <>
                  {" "}
                  <span className="fingerprint">{h.port}</span>
                  {h.service && <span className="host-meta"> {h.service}</span>}
                </>
              )}
            </li>
          ))}
          {list.total > list.items.length && <li className="host-meta">... and {list.total - list.items.length} more</li>}
        </ul>
      )}
    </>
  );

  return (
    <Modal title="Compared with the previous run" onClose={onClose} wide>
      {error && <p className="error">{error}</p>}
      {!data && !error && <p>Loading...</p>}
      {data && !data.previous && <p className="empty">This is the schedule's first completed run - there is nothing earlier to compare with.</p>}
      {data?.previous && (
        <>
          <p className="host-meta">
            This run ({formatDateTime(data.current.startedAt, me.preferences)}) against the one before it (
            {formatDateTime(data.previous.startedAt, me.preferences)}). Both scanned the same target and ports, so a
            difference is a difference in what answered.
          </p>
          {section("New hosts", data.newHosts, "No host answered that did not answer last time.")}
          {section("Hosts no longer answering", data.goneHosts, "Every host from last time answered again.")}
          {section("Ports newly open", data.opened, "No port opened on a host both runs reached.")}
          {section("Ports no longer open", data.closed, "No port closed on a host both runs reached.")}
        </>
      )}
    </Modal>
  );
}
