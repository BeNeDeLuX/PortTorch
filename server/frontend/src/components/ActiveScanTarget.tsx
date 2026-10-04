import type { ActiveScanJob } from "../api";

// A running scan's target, as the lists of running scans show it: the
// pattern it was expanded from rather than the address list it became,
// and - for one share of a split scan - which share, opening the scan as
// a whole on click. Falls back to the plain target for a scan not linked
// to a request (a local scan, or a scanner older than 0.28.0).
export default function ActiveScanTarget({ job, onOpenGroup }: { job: ActiveScanJob; onOpenGroup?: (groupId: string) => void }) {
  return (
    <>
      {job.target_pattern ? <span title={job.target_spec}>{job.target_pattern}</span> : job.target_spec}
      {job.scan_group_id && job.group_parts !== null && job.group_parts > 1 && (
        <button
          type="button"
          className="scan-part-badge"
          title="One share of a scan split across several scanners - click for the scan as a whole"
          onClick={() => onOpenGroup?.(job.scan_group_id!)}
        >
          part {job.group_part}/{job.group_parts}
        </button>
      )}
    </>
  );
}
