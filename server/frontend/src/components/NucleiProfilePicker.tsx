import { useEffect, useState } from "react";
import { api, NucleiProfile, NucleiProfileSelection } from "../api";
import { IconWarning } from "./icons";

// Shared "pick a nuclei profile" control - Off / Safe / a divider / each
// named custom profile - the independent nuclei counterpart to
// ScanProfilePicker, used alongside it (not merged with it) in
// RescanModal.tsx and Schedules.tsx's form, since NSE and nuclei are two
// orthogonal choices for the same scan. Unlike ScanProfilePicker, there's
// no way to tell client-side whether a Custom profile's tags happen to
// pull in something intrusive (nuclei has no small "known risky tags"
// list the way Active Modules scripts do - see CLAUDE.md's nuclei
// section), so any Custom pick gets the same warning rather than a
// conditional one.
export default function NucleiProfilePicker({
  value,
  onChange,
}: {
  value: NucleiProfileSelection;
  onChange: (selection: NucleiProfileSelection) => void;
}) {
  const [profiles, setProfiles] = useState<NucleiProfile[]>([]);

  useEffect(() => {
    api.nucleiProfiles().then(setProfiles).catch(() => setProfiles([]));
  }, []);

  const selectValue = value.kind === "custom" ? `custom:${value.profileId}` : value.kind;

  return (
    <>
      <select
        value={selectValue}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "off" || v === "safe") {
            onChange({ kind: v });
          } else if (v.startsWith("custom:")) {
            onChange({ kind: "custom", profileId: v.slice("custom:".length) });
          }
        }}
      >
        <option value="off">Off</option>
        <option value="safe">Safe</option>
        {profiles.length > 0 && (
          <optgroup label="Custom">
            {profiles.map((p) => (
              <option key={p.id} value={`custom:${p.id}`}>
                {p.name}
              </option>
            ))}
          </optgroup>
        )}
      </select>
      {value.kind === "custom" && (
        <div className="callout-danger">
          <IconWarning />
          <span>
            Custom nuclei profiles aren't tag-restricted the way "Safe" is - can crash a service or actively attempt
            an exploit depending on the templates its tags match. Only proceed if you're explicitly authorized to
            test the target this way.
          </span>
        </div>
      )}
    </>
  );
}
