// Shared explanation of the port-spec grammar for the two forms that take
// one (Ad-hoc Scans, Schedule Scans). Kept in one place so the two can't
// end up describing the syntax differently - the same reason
// ScanProfilePicker and ScanPriorityPicker are shared.
//
// The UDP warning is the point of it: "U:" is passed straight through to
// masscan and nmap, both of which accept that grammar natively, but a UDP
// scan behaves nothing like a TCP one. A closed UDP port usually replies
// with nothing at all rather than a refusal, so nmap has to wait out a
// timeout per port - a wide UDP range is orders of magnitude slower than
// the same TCP range, and it is genuinely easy to queue a scan that runs
// for days without meaning to.
export default function PortSpecHint() {
  return (
    <p className="empty">
      Ports are TCP unless prefixed: <code>80,443,8000-8010</code> is TCP, <code>U:53,U:161</code> is UDP, and the two
      can be mixed in one spec (<code>80,443,U:53</code>). <strong>UDP is much slower than TCP</strong> - an unanswered
      UDP probe can only be timed out, not refused, so a wide UDP range can take hours or days where the same TCP range
      takes minutes. Name the few UDP ports you actually care about rather than sweeping a range.
    </p>
  );
}
