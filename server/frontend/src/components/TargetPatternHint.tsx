// What a target pattern can say, under the Target field on Ad-hoc Scans
// and Schedule Scans - the grammar is the webserver's
// lib/targetPattern.ts, which expands it before the scanner sees it.
// "Estimate time" shows how many addresses a pattern comes to, which is
// the quickest way to catch a typo in one.
export default function TargetPatternHint() {
  return (
    <p className="empty">
      Patterns: <code>*</code> or a range like <code>1-20</code> in any octet, and <code>!</code> to leave
      addresses out. <code>10.46.*.125</code> scans only the .125 in every /24;{" "}
      <code>10.46.0.0/16 !*.2 !*.4</code> scans the /16 except .2 and .4 in each /24;{" "}
      <code>!10.46.5.0/24</code> leaves out a whole subnet. The pattern is kept as written - a schedule re-expands it
      on every run.
    </p>
  );
}
