import { describeWindowsBuild } from "../lib/windowsBuilds";
import { identitySourceLabel } from "../lib/derivedIdentity";

// The exact Windows version a scan read out of an NTLM message, wherever
// one is shown - the host list, the host detail header.
//
// It sits beside os_family rather than replacing it, because the two are
// different facts of different strength: os_family is nmap's own -O guess
// ("Windows", spanning a decade of releases, and only available at all
// when the scanner runs elevated), while this is the machine's own
// statement of its build number. On a scanner without the sudo wrapper it
// is the *only* version information there is.
//
// The release name and the support verdict are both derived here rather
// than stored (see lib/windowsBuilds.ts), so a lapsed support date
// reaches every existing host on the next deploy.
export default function WindowsBuildBadge({
  build,
  source,
}: {
  build: string | null;
  source: string | null;
}) {
  const info = describeWindowsBuild(build);
  if (!info) return null;

  // Naming the script is the same reasoning as the derived hostname's own
  // source marker: eight scripts can elicit an NTLM message, and which
  // one answered is part of reading the value.
  const title = `${info.detail} Read ${identitySourceLabel(source)}.`;

  // One inline-flex box rather than two loose siblings: in the host
  // list's wrapping badge row the marker would otherwise land on the next
  // line, detached from the version it qualifies.
  return (
    <span className="windows-build-badge">
      <span className="tech-badge" title={title}>
        {info.label ?? `Build ${info.build}`}
      </span>
      {info.outOfSupport && (
        <span className="eol-badge" title={title}>
          end of life
        </span>
      )}
    </span>
  );
}
