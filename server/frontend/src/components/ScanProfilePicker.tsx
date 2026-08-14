import { useEffect, useState } from "react";
import { api, NSEProfileSelection, ScanProfile } from "../api";
import { ACTIVE_SCRIPTS } from "../lib/nseScripts";
import { IconWarning } from "./icons";

// Shared "pick a scan profile" control - Default / All Safe Modules / a
// divider / each named custom profile - used both by RescanModal.tsx and
// Schedules.tsx's create/edit form, so the two can't drift in how a
// selection is represented (see api.ts's NSEProfileSelection). Also the
// one place that warns when the currently-selected profile is a Custom
// one containing Active Modules scripts (intrusive/exploit/brute/dos) -
// centralized here rather than duplicated in both callers, so every
// future picker usage gets the warning for free.
export default function ScanProfilePicker({
  value,
  onChange,
}: {
  value: NSEProfileSelection;
  onChange: (selection: NSEProfileSelection) => void;
}) {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);

  useEffect(() => {
    api.scanProfiles().then(setProfiles).catch(() => setProfiles([]));
  }, []);

  const selectValue = value.kind === "custom" ? `custom:${value.profileId}` : value.kind;
  const selectedProfile = value.kind === "custom" ? profiles.find((p) => p.id === value.profileId) : undefined;
  const hasActiveScripts = selectedProfile?.nse_scripts.some((s) => ACTIVE_SCRIPTS.has(s)) ?? false;

  return (
    <>
      <select
        value={selectValue}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "default" || v === "all_safe") {
            onChange({ kind: v });
          } else if (v.startsWith("custom:")) {
            onChange({ kind: "custom", profileId: v.slice("custom:".length) });
          }
        }}
      >
        <option value="default">Default</option>
        <option value="all_safe">All Safe Modules</option>
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
      {hasActiveScripts && (
        <div className="callout-danger">
          <IconWarning />
          <span>
            "{selectedProfile!.name}" includes Active Modules scripts (intrusive/exploit/brute/dos) - can crash a
            service, lock out an account, or actively attempt an exploit. Only proceed if you're explicitly
            authorized to test the target this way.
          </span>
        </div>
      )}
    </>
  );
}
