import { useEffect, useState } from "react";
import { api, NSEProfileSelection, ScanProfile } from "../api";

// Shared "pick a scan profile" control - Default / All Safe Modules / a
// divider / each named custom profile - used both by RescanModal.tsx and
// Schedules.tsx's create/edit form, so the two can't drift in how a
// selection is represented (see api.ts's NSEProfileSelection).
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

  return (
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
  );
}
